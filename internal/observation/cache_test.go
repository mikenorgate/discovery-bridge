package observation

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

func observed(t *testing.T, address string, family int, ttl uint32) Record {
	t.Helper()
	rr, err := dns.NewRR("sensor.local. 10 IN A " + address)
	if err != nil {
		t.Fatal(err)
	}
	rr.Header().Ttl = ttl
	return Record{Source: "lan-a", Generation: "link-a", Family: family, RR: rr, Flush: true}
}

func recordsAt(t *testing.T, c *Cache, seconds float64) []catalog.Record {
	t.Helper()
	values, err := c.Records(catalog.Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Duration(seconds * float64(time.Second))})
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestHintsRequireExactWireEvidenceAndCannotRenewTTL(t *testing.T) {
	c := New()
	r := observed(t, "192.0.2.42", 4, 5)
	if err := c.Ingest([]Record{r}, 0); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 0)) != 0 {
		t.Fatal("wire alone became an exported record")
	}
	foreign := r
	foreign.Generation = "link-b"
	if err := c.Hint("browser", foreign, true); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 0)) != 0 {
		t.Fatal("foreign generation supplied a hint")
	}
	if err := c.Hint("browser", r, true); err != nil {
		t.Fatal(err)
	}
	values := recordsAt(t, c, 1)
	if len(values) != 1 || values[0].Expires.Sub(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) != 4*time.Second {
		t.Fatal(values)
	}
	if err := c.Hint("browser", r, true); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 5)) != 0 {
		t.Fatal("cached hint renewed an expired wire record")
	}
	if err := c.Ingest([]Record{r}, 6*time.Second); err != nil {
		t.Fatal(err)
	}
	c.ForgetEpoch("browser")
	if len(recordsAt(t, c, 6)) != 0 {
		t.Fatal("lost Avahi epoch remained authoritative")
	}
}

func TestFlushAndGoodbyeCrossFamiliesWithOneSecondGrace(t *testing.T) {
	c := New()
	old, fresh := observed(t, "192.0.2.42", 6, 10), observed(t, "192.0.2.43", 4, 10)
	for _, r := range []Record{old, fresh} {
		if err := c.Hint("browser", r, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Ingest([]Record{old}, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Ingest([]Record{fresh}, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, .2)) != 2 {
		t.Fatal("flush removed an observation received within one second")
	}
	if err := c.Ingest([]Record{fresh}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 3)) != 1 {
		t.Fatal("old family survived cache-flush grace")
	}
	goodbye := observed(t, "192.0.2.43", 6, 0)
	if err := c.Ingest([]Record{goodbye}, 4*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 5)) != 0 {
		t.Fatal("other-family goodbye failed to withdraw the record")
	}
}

func TestCorrelatedFamiliesShareIdentityAndShortestExpiry(t *testing.T) {
	c := New()
	for _, r := range []Record{observed(t, "192.0.2.42", 4, 10), observed(t, "192.0.2.42", 6, 5)} {
		if err := c.Hint("browser", r, true); err != nil {
			t.Fatal(err)
		}
		if err := c.Ingest([]Record{r}, 0); err != nil {
			t.Fatal(err)
		}
	}
	values := recordsAt(t, c, 0)
	if len(values) != 1 || len(values[0].ID) != 64 || values[0].Expires.Sub(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) != 5*time.Second {
		t.Fatal(values)
	}
	c.ForgetLink("lan-a", "link-a")
	if len(recordsAt(t, c, 0)) != 0 {
		t.Fatal("replaced link retained evidence")
	}
}

func TestCapacityAndClockFailureDiscardTheEpoch(t *testing.T) {
	c := New()
	var records []Record
	for index := range catalog.MaxRecords + 1 {
		r := observed(t, "192.0.2.42", 4, 10)
		r.RR.Header().Name = fmt.Sprintf("client-%d.local.", index)
		records = append(records, r)
	}
	if err := c.Ingest(records, 0); err == nil {
		t.Fatal("observation capacity was unbounded")
	}
	if wire, hints := c.Counts(); wire != 0 || hints != 0 {
		t.Fatal("failed epoch retained authority", wire, hints)
	}
	if _, err := c.Records(catalog.Now()); err == nil {
		t.Fatal("capacity failure silently recovered")
	}
	c = New()
	if err := c.Ingest(records[:1], 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Records(catalog.Moment{Wall: time.Now().UTC(), Mono: time.Second}); err == nil {
		t.Fatal("backwards clock retained observations")
	}
}

func TestQueuedWireEvidenceKeepsReceiveExpiryAndNewerObservations(t *testing.T) {
	c := New()
	r := observed(t, "192.0.2.42", 4, 5)
	if err := c.Hint("browser", r, true); err != nil {
		t.Fatal(err)
	}
	if err := c.IngestAt([]Record{r}, time.Second, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if values := recordsAt(t, c, 3); len(values) != 1 || values[0].Expires.Sub(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) != 3*time.Second {
		t.Fatal("queued observation acquired extra lifetime", values)
	}
	if err := c.IngestAt([]Record{r}, 5*time.Second, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	goodbye := observed(t, "192.0.2.42", 6, 0)
	if err := c.IngestAt([]Record{goodbye}, 2*time.Second, 6*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.IngestAt([]Record{r}, time.Second, 6*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 7)) != 1 || len(recordsAt(t, c, 10)) != 0 {
		t.Fatal("late old data or goodbye replaced a newer observation")
	}
	if err := c.IngestAt([]Record{r}, time.Second, 11*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 11)) != 0 {
		t.Fatal("already expired queued data reappeared")
	}
}

func TestQueuedOldRRSetCannotReappearAfterNewFlushExpires(t *testing.T) {
	c := New()
	old, fresh := observed(t, "192.0.2.42", 4, 30), observed(t, "192.0.2.43", 6, 1)
	for _, r := range []Record{old, fresh} {
		if err := c.Hint("browser", r, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.IngestAt([]Record{fresh}, 2*time.Second, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 3)) != 0 {
		t.Fatal("new flush did not expire")
	}
	if err := c.IngestAt([]Record{old}, 0, 4*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 4)) != 0 {
		t.Fatal("delayed old RRset escaped newer cross-family cache flush")
	}
	if err := c.IngestAt([]Record{old}, 4*time.Second, 4*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(recordsAt(t, c, 4)) != 1 {
		t.Fatal("fresh wire evidence was withheld after a flush")
	}
}
