package state_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func openIdentities(t *testing.T) *state.Identities {
	t.Helper()
	s, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "identities.sqlite"), "db-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAliasLookupPreservesCaseAndRetiredReservations(t *testing.T) {
	s, ctx := openIdentities(t), context.Background()
	_, first, err := s.Alias(ctx, "lan-a", "Demo._http._tcp.local.", false)
	if err != nil || !strings.HasPrefix(first, "Demo-") {
		t.Fatal("new alias lost its display label", first, err)
	}
	if source, original, err := s.Original(ctx, strings.ToUpper(first)); err != nil || source != "lan-a" || original != "demo._http._tcp.local." {
		t.Fatal("case-insensitive lookup lost its source", source, original, err)
	}
	second, err := s.RotateAlias(ctx, first)
	if err != nil || second == first || second == "" {
		t.Fatal(second, err)
	}
	if _, _, err := s.Original(ctx, first); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("retired alias was still queryable", err)
	}
	if owned, err := s.Owns(ctx, first); err != nil || !owned {
		t.Fatal("retired reservation was released", err)
	}
}

func TestOriginalHostCollisionKeepsServiceAliasesStable(t *testing.T) {
	s, ctx := openIdentities(t), context.Background()
	_, host, err := s.Alias(ctx, "lan-a", "sensor.local.", false)
	if err != nil {
		t.Fatal(err)
	}
	_, service, err := s.Alias(ctx, "lan-a", "Demo._http._tcp.local.", false)
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := s.OwnsHost(ctx, "lan-a", "SENSOR.local."); err != nil || !owned {
		t.Fatal("observed original was not source-scoped", err)
	}
	for _, query := range [][2]string{{"lan-b", "sensor.local."}, {"lan-a", host}, {"lan-a", service}} {
		if owned, err := s.OwnsHost(ctx, query[0], query[1]); err != nil || owned {
			t.Fatal("unobserved host or alias treated as original", query, err)
		}
	}
	if err := s.ResolveConflicts(ctx, []string{"SENSOR.local.", host, service}); err != nil {
		t.Fatal(err)
	}
	blocked := s.SuppressedHosts()
	if !blocked["sensor.local."] {
		t.Fatal(blocked)
	}
	delete(blocked, "sensor.local.")
	if !s.SuppressedHosts()["sensor.local."] {
		t.Fatal("suppression map was externally mutable")
	}
	_, after, err := s.Alias(ctx, "lan-a", "Demo._http._tcp.local.", false)
	if err != nil || after != service {
		t.Fatal("original collision rotated a stable service", after, err)
	}
}

func TestCompiledAliasesKeepChainsWithinTheirSourceAndExpiry(t *testing.T) {
	s, ctx := openIdentities(t), context.Background()
	now := time.Now().UTC()
	var records []catalog.Record
	for _, source := range []string{"lan-a", "lan-b"} {
		data := "192.0.2.42"
		if source == "lan-b" {
			data = "198.51.100.42"
		}
		for _, r := range []catalog.Record{
			{ID: "browse", Name: "_http._tcp.local.", Type: "PTR", Data: "Demo._http._tcp.local."},
			{ID: "srv", Name: "Demo._http._tcp.local.", Type: "SRV", Data: "0 0 8080 sensor.local."},
			{ID: "txt", Name: "Demo._http._tcp.local.", Type: "TXT", Data: `"path=/"`},
			{ID: "host", Name: "sensor.local.", Type: "A", Data: data},
		} {
			r.ID, r.Source, r.Expires = source+"-"+r.ID, source, now.Add(8*time.Second)
			records = append(records, r)
		}
	}
	view, err := s.Compile(ctx, records, now)
	if err != nil || len(view) != 8 {
		t.Fatal("scoped service chains were lost", len(view), err)
	}
	for _, answer := range view {
		if answer.RR.Header().Ttl != 8 {
			t.Fatal("source lifetime changed", answer)
		}
		if srv, ok := answer.RR.(*dns.SRV); ok {
			_, host, err := s.Alias(ctx, answer.Source, "sensor.local.", false)
			if err != nil || srv.Target != host || !answer.Unique {
				t.Fatal("service joined a foreign target", answer, err)
			}
		}
	}
	if expired, err := s.Compile(ctx, records, now.Add(8*time.Second)); err != nil || len(expired) != 0 {
		t.Fatal("expired aliases remained visible", expired, err)
	}
}
