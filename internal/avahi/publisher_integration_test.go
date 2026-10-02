//go:build integration

package avahi

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

type publicationFixture struct {
	conn                                         *dbus.Conn
	mu                                           sync.Mutex
	exports                                      sync.Mutex
	serial, active, peak, commits, resets, frees int
	delay                                        time.Duration
	paths                                        map[dbus.ObjectPath]bool
}

func publisherFixture(t *testing.T, path string, delay time.Duration) *publicationFixture {
	t.Helper()
	service := avahiFixture(t, path, nil)
	f := &publicationFixture{conn: service.conn, delay: delay, paths: make(map[dbus.ObjectPath]bool)}
	if err := f.conn.ExportMethodTable(map[string]any{
		"GetState":      func() (int32, *dbus.Error) { return 2, nil },
		"EntryGroupNew": f.newGroup,
	}, "/", server); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *publicationFixture) wait() func() {
	f.mu.Lock()
	f.active++
	f.peak = max(f.peak, f.active)
	f.mu.Unlock()
	time.Sleep(f.delay)
	return func() { f.mu.Lock(); f.active--; f.mu.Unlock() }
}

func (f *publicationFixture) newGroup() (dbus.ObjectPath, *dbus.Error) {
	defer f.wait()()
	// godbus' export registration reads its object map outside its own lock.
	// Serialize fixture registration; the production adapter exports no methods.
	f.exports.Lock()
	defer f.exports.Unlock()
	f.mu.Lock()
	f.serial++
	path := dbus.ObjectPath(fmt.Sprintf("/group/%d", f.serial))
	f.paths[path] = true
	f.mu.Unlock()
	err := f.conn.ExportMethodTable(map[string]any{
		"AddRecord": func(index, protocol int32, flags uint32, name string, class, kind uint16, ttl uint32, raw []byte) *dbus.Error {
			defer f.wait()()
			if index < 1 || (protocol != 0 && protocol != 1) || flags != 9 || class != dns.ClassINET || ttl != 1 {
				return dbus.MakeFailedError(fmt.Errorf("invalid publication fields"))
			}
			if _, err := rawRecord(name, kind, raw); err != nil {
				return dbus.MakeFailedError(err)
			}
			return nil
		},
		"Commit": func() *dbus.Error { defer f.wait()(); f.mu.Lock(); f.commits++; f.mu.Unlock(); return nil },
		"Reset":  func() *dbus.Error { defer f.wait()(); f.mu.Lock(); f.resets++; f.mu.Unlock(); return nil },
		"Free": func() *dbus.Error {
			defer f.wait()()
			f.mu.Lock()
			f.frees++
			delete(f.paths, path)
			f.mu.Unlock()
			return nil
		},
	}, path, groupInterface)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return path, nil
}

func TestPublisherParallelGroupsRenewalAndReplacementDeadlines(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 20*time.Millisecond)
	links := make(map[int]observation.Link)
	for index := 1; index <= 6; index++ {
		links[index] = observation.Link{Source: fmt.Sprintf("lan-%d", index), Generation: "link-a", Families: []int{4, 6}}
	}
	var mu sync.Mutex
	goodbyes := 0
	p, err := ConnectPublisher(context.Background(), path, links, func(_ context.Context, _, _ int, values []catalog.Answer) error {
		if len(values) != 1 {
			t.Error("unexpected goodbye signature")
		}
		mu.Lock()
		goodbyes++
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("alias.local. 10 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	var intents []Intent
	for index := range links {
		for _, family := range []int{4, 6} {
			intents = append(intents, Intent{index, family, catalog.Now().Mono + time.Second, []catalog.Answer{{RR: rr, Unique: true}}})
		}
	}
	start := time.Now()
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) >= time.Second {
		t.Fatal("parallel groups exceeded short lease")
	}
	f.mu.Lock()
	peak, commits := f.peak, f.commits
	f.mu.Unlock()
	if peak <= 1 || peak > 12 || commits != 12 {
		t.Fatal("groups did not run with bounded concurrency", peak, commits)
	}
	// An unchanged renewal extends the lease without another Commit.
	for i := range intents {
		intents[i].Deadline = catalog.Now().Mono + 2*time.Second
	}
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	commits = f.commits
	f.mu.Unlock()
	if commits != 12 {
		t.Fatal("unchanged groups were republished")
	}
	// Removal must finish within the old lease, but replacement creation uses
	// its own deadline once those old groups have actually been withdrawn.
	p.mu.Lock()
	for key, group := range p.groups {
		group.deadline = catalog.Now().Mono + 150*time.Millisecond
		p.groups[key] = group
	}
	p.mu.Unlock()
	for i := range intents {
		intents[i].Records[0].RR = dns.Copy(rr)
		intents[i].Records[0].RR.(*dns.A).A = []byte{192, 0, 2, 43}
		intents[i].Deadline = catalog.Now().Mono + time.Second
	}
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal("replacement reused withdrawn deadline", err)
	}
	if err := p.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	if groups, records := p.Counts(); groups != 0 || records != 0 {
		t.Fatal("producer clear retained publication")
	}
	mu.Lock()
	removed := goodbyes
	mu.Unlock()
	if removed != 24 {
		t.Fatal("replacement or clear omitted scoped goodbyes", removed)
	}
}

func TestPublisherExpiresIndependentlyAndReportsConflicts(t *testing.T) {
	for _, reason := range []string{"lease", "conflict"} {
		t.Run(reason, func(t *testing.T) {
			path := privateBus(t)
			f := publisherFixture(t, path, 0)
			p, err := ConnectPublisher(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}, func(context.Context, int, int, []catalog.Answer) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := p.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			rr, err := dns.NewRR("alias.local. 30 IN A 192.0.2.42")
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Reconcile(context.Background(), []Intent{{2, 4, catalog.Now().Mono + 150*time.Millisecond, []catalog.Answer{{RR: rr, Unique: true}}}}); err != nil {
				t.Fatal(err)
			}
			if reason == "conflict" {
				p.mu.Lock()
				group := p.groups[groupKey{2, 4}]
				p.mu.Unlock()
				if err := f.conn.Emit(group.path, groupInterface+".StateChanged", int32(3), "conflict"); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-p.Failed():
			case <-time.After(time.Second):
				t.Fatal("independent publication monitor did not withdraw")
			}
			if p.Err() == nil {
				t.Fatal("lost epoch remained available")
			}
			if reason == "conflict" {
				if names := p.Conflicts(); len(names) != 1 || names[0] != "alias.local." {
					t.Fatal(names)
				}
			}
			if err := p.Reconcile(context.Background(), nil); err == nil {
				t.Fatal("failed connection accepted renewal")
			}
		})
	}
}

func TestSlowReconciliationCannotExtendPublicationLease(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 100*time.Millisecond)
	p, err := ConnectPublisher(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}, func(context.Context, int, int, []catalog.Answer) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("alias.local. 30 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = p.Reconcile(context.Background(), []Intent{{2, 4, catalog.Now().Mono + 150*time.Millisecond, []catalog.Answer{{RR: rr, Unique: true}}}})
	if err == nil || p.Err() == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatal("slow D-Bus extended lease", err, time.Since(start))
	}
	f.mu.Lock()
	commits := f.commits
	f.mu.Unlock()
	if commits != 0 {
		t.Fatal("expired creation committed records")
	}
}
