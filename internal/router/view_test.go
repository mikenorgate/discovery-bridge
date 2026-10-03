package router

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func deviceRecords(t *testing.T, now time.Time) []catalog.Record {
	t.Helper()
	var values []catalog.Record
	for i, fields := range [][3]string{
		{catalog.Enumeration, "PTR", "_example._tcp.local."},
		{"_example._tcp.local.", "PTR", "Sensor._example._tcp.local."},
		{"Sensor._example._tcp.local.", "SRV", "0 0 8080 sensor.local."},
		{"Sensor._example._tcp.local.", "TXT", `"version=1"`},
		{"sensor.local.", "A", "192.0.2.42"},
		{"sensor.local.", "AAAA", "2001:db8:1::42"},
	} {
		values = append(values, catalog.Record{ID: string(rune('a' + i)), Name: fields[0], Type: fields[1], Data: fields[2], Source: "lan-a", Expires: now.Add(10 * time.Second)})
	}
	return values
}

func TestLANOwnershipAndPodNamesHaveIndependentViews(t *testing.T) {
	ctx := context.Background()
	identities, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"), "bridge")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = identities.Close() }()
	now := catalog.Moment{Wall: time.Now().UTC(), Mono: time.Minute}
	records := deviceRecords(t, now.Wall)
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "a", Families: []int{4, 6}}, 3: {Source: "lan-b", Generation: "b", Families: []int{6}}}
	groups, err := lanGroups(ctx, records, identities, links, now)
	if err != nil || len(groups) != 3 {
		t.Fatal(groups, err)
	}
	for _, group := range groups {
		if group.Deadline != now.Mono+10*time.Second {
			t.Fatal("publication extended source lease", group.Deadline)
		}
		hosts := 0
		for _, answer := range group.Records {
			if catalog.NameKey(answer.RR.Header().Name) == "sensor.local." {
				hosts++
				if !answer.Unique || group.Interface == 2 {
					t.Fatal("original host advertised without ownership or on its origin")
				}
			}
		}
		if group.Interface == 3 && hosts != 2 {
			t.Fatal("original v4/v6 host missing on another LAN", hosts)
		}
	}
	for _, answer := range podView(records, now.Wall) {
		if answer.Unique {
			t.Fatal("pod received an exclusive claim")
		}
		if answer.RR.Header().Rrtype == dns.TypeSRV && answer.RR.(*dns.SRV).Target != "sensor.local." {
			t.Fatal("pod application target renamed")
		}
	}
	// An expiring address dependency is removed before compilation, withholding
	// its dependent service while pod records retain their shorter native TTL.
	for i := 4; i < 6; i++ {
		records[i].Expires = now.Wall.Add(4 * time.Second)
	}
	groups, err = lanGroups(ctx, records, identities, links, now)
	if err != nil || len(podView(records, now.Wall)) != 6 {
		t.Fatal("early LAN withdrawal changed pod TTLs or exposed incomplete chains", groups, err)
	}
	for _, group := range groups {
		for _, answer := range group.Records {
			if catalog.NameKey(answer.RR.Header().Name) != catalog.Enumeration {
				t.Fatal("expiring address left a dependent service advertised", answer)
			}
		}
	}
}

func TestLocalPublisherLockDoesNotUnlinkAnActiveOrForeignPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publisher.sock")
	listener, lock, err := localListener(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close(); _ = listener.Close() }()
	if competing, competingLock, err := localListener(path); err == nil {
		_ = competing.Close()
		_ = competingLock.Close()
		t.Fatal("second publisher acquired an active path")
	}
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal("active IPC socket was unlinked", err)
	}
	_ = connection.Close()
}
