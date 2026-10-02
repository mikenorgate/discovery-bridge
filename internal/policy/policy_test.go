package policy_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

func TestNativeScope(t *testing.T) {
	t.Parallel()
	p, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}, "lan-b": {"198.51.100.0/24"}}, []string{"2001:db8:1::80/128"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, source, address string
		valid                 bool
	}{
		{"native v4", "lan-a", "192.0.2.80", true}, {"native v6", "lan-a", "2001:db8:1::81", true},
		{"wrong source", "lan-b", "192.0.2.80", false}, {"unknown source", "missing", "192.0.2.80", false},
		{"excluded", "lan-a", "2001:db8:1::80", false}, {"network", "lan-a", "192.0.2.0", false},
		{"broadcast", "lan-a", "192.0.2.255", false}, {"multicast", "lan-a", "224.0.0.251", false},
		{"mapped", "lan-a", "::ffff:192.0.2.80", false}, {"scoped", "lan-a", "2001:db8:1::80%eth0", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := p.CheckAddress(test.source, netip.MustParseAddr(test.address))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v: %v", test.valid, err)
			}
		})
	}
	copy := p.Sources()
	copy["lan-a"][0] = netip.MustParsePrefix("203.0.113.0/24")
	if err := p.CheckAddress("lan-a", netip.MustParseAddr("192.0.2.80")); err != nil {
		t.Fatal("caller mutated source policy")
	}
}

func TestTTLNeverRenewsExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		name  string
		delta time.Duration
		want  uint32
	}{
		{"bounded", 45 * time.Second, 30}, {"floor", 1900 * time.Millisecond, 1},
		{"subsecond", 900 * time.Millisecond, 0}, {"expired", -time.Second, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.RemainingTTL(now, 30, now.Add(test.delta)); got != test.want {
				t.Fatalf("got %d; want %d", got, test.want)
			}
		})
	}
	if policy.RemainingTTL(now, 30, now.Add(20*time.Second), now.Add(time.Second)) != 1 {
		t.Fatal("shortest deadline ignored")
	}
}

func TestNAT46RequiresExistingReadyMapping(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	base := policy.Mapping{EndpointID: "endpoint-1", Target: netip.MustParseAddr("2001:db8:2::22"), Alias: netip.MustParseAddr("192.0.2.42"), DesiredGeneration: 7, InstalledGeneration: 7, AcknowledgedGeneration: 7, State: "ready", ValidUntil: now.Add(10 * time.Second)}
	pool := netip.MustParsePrefix("192.0.2.0/24")
	if !base.Ready(base.EndpointID, base.Target, pool, nil, now) {
		t.Fatal("ready mapping rejected")
	}
	for _, test := range []struct {
		name   string
		change func(*policy.Mapping)
	}{
		{"absent", func(m *policy.Mapping) { *m = policy.Mapping{} }},
		{"not installed", func(m *policy.Mapping) { m.InstalledGeneration = 6 }},
		{"not acknowledged", func(m *policy.Mapping) { m.AcknowledgedGeneration = 6 }},
		{"pending", func(m *policy.Mapping) { m.State = "pending" }},
		{"wrong endpoint", func(m *policy.Mapping) { m.EndpointID = "other" }},
		{"wrong target", func(m *policy.Mapping) { m.Target = netip.MustParseAddr("2001:db8:2::23") }},
		{"expired", func(m *policy.Mapping) { m.ValidUntil = now }},
		{"outside pool", func(m *policy.Mapping) { m.Alias = netip.MustParseAddr("198.51.100.42") }},
		{"broadcast", func(m *policy.Mapping) { m.Alias = netip.MustParseAddr("192.0.2.255") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := base
			test.change(&m)
			if m.Ready(base.EndpointID, base.Target, pool, nil, now) {
				t.Fatal("unready mapping accepted")
			}
		})
	}
	if base.Ready(base.EndpointID, base.Target, pool, []netip.Addr{base.Alias}, now) {
		t.Fatal("reserved alias accepted")
	}
}

func TestNAT64UsesConfiguredPrefix(t *testing.T) {
	t.Parallel()
	got, err := policy.NAT64(netip.MustParsePrefix("2001:db8:64::/96"), netip.MustParseAddr("192.0.2.80"))
	if err != nil || got.String() != "2001:db8:64::c000:250" {
		t.Fatalf("got %s: %v", got, err)
	}
	if _, err := policy.NAT64(netip.MustParsePrefix("64:ff9b::/96"), netip.MustParseAddr("10.0.0.80")); err == nil {
		t.Fatal("private IPv4 allowed under well-known prefix")
	}
	if _, err := policy.NAT64(netip.MustParsePrefix("2001:db8::/64"), netip.MustParseAddr("192.0.2.80")); err == nil {
		t.Fatal("unsupported prefix accepted")
	}
}
