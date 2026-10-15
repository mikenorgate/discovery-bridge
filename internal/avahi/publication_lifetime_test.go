package avahi

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

func TestPublicationCacheLifetimeStaysInsideLongEvidenceLease(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		remaining time.Duration
		ttl       uint32
		reserve   time.Duration
	}{
		{name: "maximum lease", remaining: 30 * time.Second, ttl: 5, reserve: 6 * time.Second},
		{name: "long lease threshold", remaining: 10 * time.Second, ttl: 5, reserve: 6 * time.Second},
		{name: "short lease", remaining: 10*time.Second - time.Nanosecond, ttl: 1},
		{name: "nearly expired", remaining: 150 * time.Millisecond, ttl: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rr, err := dns.NewRR("alias.local. 1 IN A 192.0.2.42")
			if err != nil {
				t.Fatal(err)
			}
			now := 100 * time.Second
			intent := Intent{
				Interface: 2,
				Family:    4,
				Deadline:  now + test.remaining,
				Records:   []catalog.Answer{{RR: rr, Unique: true}},
			}
			p := &Publisher{links: map[int]observation.Link{
				2: {Source: "lan-a", Generation: "link-a", Families: []int{4}},
			}}
			desired, err := p.validate([]Intent{intent}, now)
			if err != nil {
				t.Fatal(err)
			}
			result := desired[groupKey{index: 2, family: 4}]
			if result.Deadline != intent.Deadline-test.reserve || result.Records[0].RR.Header().Ttl != test.ttl {
				t.Fatalf("deadline=%v ttl=%d", result.Deadline, result.Records[0].RR.Header().Ttl)
			}
			if test.ttl > 1 && result.Deadline+time.Duration(test.ttl)*time.Second > intent.Deadline {
				t.Fatal("last Avahi reply can outlive evidence even without a goodbye")
			}
			if rr.Header().Ttl != 1 {
				t.Fatal("caller-owned record was modified")
			}
		})
	}
}
