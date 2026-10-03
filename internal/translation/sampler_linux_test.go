package translation

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"golang.org/x/sys/unix"
)

const config46 = `tun-device xlate46
ipv4-addr 198.51.100.1
ipv6-addr 2001:db8:46:ffff::1
prefix 2001:db8:46::/96
map 198.51.100.42 2001:db8:1::42
data-dir /var/lib/translator46
`
const config64 = `tun-device xlate64
ipv4-addr 203.0.113.1
ipv6-addr 2001:db8:64:ffff::1
prefix 2001:db8:64::/96
dynamic-pool 203.0.113.0/24
udp-cksum-mode calc
data-dir /var/lib/translator64
`

func fixture(t *testing.T) *Sampler {
	t.Helper()
	settings := &config.Translators{
		Translation: config.Translation{NAT64Prefix: "2001:db8:64::/96", NAT46Pool: "198.51.100.0/24", Reserved: []string{"198.51.100.1"}},
		IP:          []string{"/usr/sbin/ip"}, Systemctl: []string{"/usr/bin/systemctl"},
		NAT46: &config.Translator{Interface: "xlate46", Unit: "translator46.service", Config: "/etc/translator46.conf", Binary: "/usr/sbin/tayga", IPv4: "198.51.100.1", IPv6: "2001:db8:46:ffff::1", Prefix: "2001:db8:46::/96", DataDirectory: "/var/lib/translator46"},
		NAT64: &config.Translator{Interface: "xlate64", Unit: "translator64.service", Config: "/etc/translator64.conf", Binary: "/usr/sbin/tayga", IPv4: "203.0.113.1", IPv6: "2001:db8:64:ffff::1", Prefix: "2001:db8:64::/96", DataDirectory: "/var/lib/translator64", DynamicPool: "203.0.113.0/24"},
	}
	s, err := New(settings, []config.LAN{{Interface: "lan0"}})
	if err != nil {
		t.Fatal(err)
	}
	// Mutation by the config owner cannot alter authority after construction.
	settings.IP[0], settings.NAT46.Interface, settings.Reserved[0] = "/unavailable", "other", "198.51.100.42"
	return s
}

func kernelFixture(t *testing.T) ([]link, []route) {
	t.Helper()
	links, err := decodeList[link]([]byte(`[
{"ifname":"xlate46","flags":["UP"],"linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}},"addr_info":[{"local":"198.51.100.1"},{"local":"2001:db8:46:ffff::1"}]},
{"ifname":"xlate64","flags":["UP"],"linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}},"addr_info":[{"local":"203.0.113.1"},{"local":"2001:db8:64:ffff::1"}]}
]`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	routes := []route{
		{Destination: "2001:db8:46::/96", Device: "xlate46"}, {Destination: "198.51.100.0/24", Device: "xlate46"},
		{Destination: "2001:db8:64::/96", Device: "xlate64"}, {Destination: "203.0.113.0/24", Device: "xlate64"},
		{Destination: "2001:db8:1::/64", Device: "lan0"},
	}
	return links, routes
}

func TestImmutableProfilesCannotAllocateOrAcceptExternalMaps(t *testing.T) {
	s := fixture(t)
	maps, err := parseConfig([]byte(config46), *s.settings.NAT46, s.spaces, true)
	if err != nil || maps[netip.MustParseAddr("2001:db8:1::42")] != netip.MustParseAddr("198.51.100.42") {
		t.Fatal(maps, err)
	}
	for _, data := range []string{
		config46 + "map-file /etc/maps\n", config46 + "prefix 2001:db8:46::/96\n", config46 + "map 198.51.100.42 2001:db8:1::43\n",
		config46 + "map 198.51.100.43 2001:db8:1::42\n", strings.ReplaceAll(config46, "198.51.100.42", "198.51.100.1"),
		strings.ReplaceAll(config46, "198.51.100.42", "198.51.100.255"), strings.ReplaceAll(config46, "198.51.100.42", "192.0.2.42"),
		strings.ReplaceAll(config46, "2001:db8:1::42", "fe80::42"), strings.ReplaceAll(config46, "2001:db8:1::42", "2001:db8:64::42"),
		strings.ReplaceAll(config46, "2001:db8:1::42", "2001:db8:46::42"), strings.ReplaceAll(config46, "tun-device xlate46", "tun-device lan0"),
		config46 + "#é\n", strings.ReplaceAll(config46, "map 198.51.100.42 2001:db8:1::42\n", ""),
	} {
		if _, err := parseConfig([]byte(data), *s.settings.NAT46, s.spaces, true); err == nil {
			t.Fatal("unsafe static translator profile accepted", data)
		}
	}
	if maps, err := parseConfig([]byte(config64), *s.settings.NAT64, s.spaces, false); err != nil || len(maps) != 0 {
		t.Fatal(maps, err)
	}
	if _, err := parseConfig([]byte(strings.ReplaceAll(config64, "calc", "ignore")), *s.settings.NAT64, s.spaces, false); err == nil {
		t.Fatal("unverified UDP checksum mode accepted")
	}
}

func TestTargetRequiresSpecificUsableLANRoute(t *testing.T) {
	s := fixture(t)
	links, routes := kernelFixture(t)
	target := netip.MustParseAddr("2001:db8:1::42")
	if !installed(*s.settings.NAT46, s.spaces, true, links, routes) || !targetRouted(target, routes, s.lans) {
		t.Fatal("installed fixture rejected")
	}
	for _, additions := range [][]route{
		{{Destination: target.String() + "/128", Type: "blackhole"}},
		{{Destination: target.String(), Type: "blackhole"}},
		{{Destination: target.String() + "/128", Device: "wan0"}},
		{{Destination: "2001:db8:1::/64", Device: "wan0"}},
		{{Destination: target.String() + "/128", Device: "lan0", Flags: []string{"linkdown"}}},
		{{Destination: target.String() + "/128", Device: "lan0", Multipath: json.RawMessage(`[]`)}},
	} {
		if targetRouted(target, append(slices.Clone(routes), additions...), s.lans) {
			t.Fatal("unusable winning route accepted", additions)
		}
	}
	if targetRouted(target, []route{{Destination: "default", Device: "lan0"}}, s.lans) || targetRouted(target, routes[:4], s.lans) {
		t.Fatal("default/missing target route accepted")
	}
	if installed(*s.settings.NAT46, s.spaces, true, links, routes[1:]) {
		t.Fatal("missing TUN route accepted")
	}
	for _, modify := range []func([]link){
		func(ls []link) { ls[0].Flags = nil },
		func(ls []link) { ls[0].Info.Kind = "veth" },
		func(ls []link) { ls[0].Addresses[0].Tentative = true },
		func(ls []link) { ls[0].Addresses[0].Preferred = json.RawMessage(`0`) },
	} {
		links, _ := kernelFixture(t)
		modify(links)
		if installed(*s.settings.NAT46, s.spaces, true, links, routes) {
			t.Fatal("unready TUN accepted")
		}
	}
	if _, err := decodeList[link]([]byte(`[{"ifname":"good","ifname":"bad"}]`), 1024); err == nil {
		t.Fatal("duplicate kernel authority accepted")
	}
}

type scripted struct {
	s            *Sampler
	links        []link
	routes       []route
	calls        [][]string
	serviceCalls map[string]int
	replace      bool
	missing46    bool
	mutable      bool
	badKernel    bool
	reads        int
}

func scriptedObserver(t *testing.T, s *Sampler) *scripted {
	t.Helper()
	links, routes := kernelFixture(t)
	x := &scripted{s: s, links: links, routes: routes, serviceCalls: make(map[string]int)}
	s.observer = observer{run: x.run, read: x.read, args: x.args}
	return x
}

func (x *scripted) run(_ context.Context, argv []string, timeout time.Duration, limit int) ([]byte, error) {
	x.calls = append(x.calls, slices.Clone(argv))
	if timeout != time.Second || limit > 1_048_576 {
		return nil, errors.New("unbounded observation")
	}
	if argv[0] == "/usr/sbin/ip" {
		if x.badKernel {
			return []byte(`[] {}`), nil
		}
		if reflect.DeepEqual(argv[1:], []string{"-j", "-d", "address", "show"}) {
			return json.Marshal(x.links)
		}
		if reflect.DeepEqual(argv[1:], []string{"-j", "-4", "route", "show"}) {
			return []byte(`[]`), nil
		}
		if reflect.DeepEqual(argv[1:], []string{"-j", "-6", "route", "show"}) {
			return json.Marshal(x.routes)
		}
		return nil, errors.New("unexpected ip mutation")
	}
	if len(argv) != 4 || argv[0] != "/usr/bin/systemctl" || argv[1] != "show" || argv[3] != "--property=ActiveState,SubState,MainPID,InvocationID" {
		return nil, errors.New("unexpected service mutation")
	}
	unit := argv[2]
	x.serviceCalls[unit]++
	if x.missing46 && unit == x.s.settings.NAT46.Unit {
		return nil, errors.New("unavailable")
	}
	invocation := "a"
	if x.replace && x.serviceCalls[unit]%2 == 0 {
		invocation = "b"
	}
	pid := "123"
	if unit == x.s.settings.NAT64.Unit {
		pid = "124"
	}
	return []byte("ActiveState=active\nSubState=running\nMainPID=" + pid + "\nInvocationID=" + strings.Repeat(invocation, 32) + "\n"), nil
}

func (x *scripted) read(path string) ([]byte, error) {
	x.reads++
	data := config64
	if path == x.s.settings.NAT46.Config {
		data = config46
	}
	if x.mutable && x.reads%2 == 0 {
		data += "# changed\n"
	}
	return []byte(data), nil
}

func (x *scripted) args(pid int) ([]byte, error) {
	profile := x.s.settings.NAT46
	if pid == 124 {
		profile = x.s.settings.NAT64
	}
	return []byte(profile.Binary + "\x00--nodetach\x00--config\x00" + profile.Config + "\x00--pidfile\x00/run/translator.pid\x00--user\x00tayga\x00--group\x00tayga\x00"), nil
}

func TestObservationChecksServiceAndConfigOnBothSides(t *testing.T) {
	s := fixture(t)
	x := scriptedObserver(t, s)
	value := s.observer.observe(context.Background(), s.settings, s.spaces, s.lans)
	if !value.nat64 || len(value.maps) != 1 || value.generation == 0 {
		t.Fatal("ready instances withheld", value)
	}
	for _, change := range []func(*scripted){
		func(x *scripted) { x.replace = true }, func(x *scripted) { x.mutable = true }, func(x *scripted) { x.badKernel = true },
	} {
		s := fixture(t)
		x := scriptedObserver(t, s)
		change(x)
		value := s.observer.observe(context.Background(), s.settings, s.spaces, s.lans)
		if value.nat64 || len(value.maps) != 0 {
			t.Fatal("changed/unavailable authority remained ready", value)
		}
	}
	x.missing46 = true
	value = s.observer.observe(context.Background(), s.settings, s.spaces, s.lans)
	if !value.nat64 || len(value.maps) != 0 {
		t.Fatal("one failed instance withdrew independent readiness")
	}
	for _, args := range []string{
		"/usr/sbin/tayga\x00--config\x00/etc/translator46.conf\x00--config\x00/etc/other.conf\x00--nodetach\x00",
		"/usr/sbin/tayga\x00--config\x00/etc/translator46.conf\x00--nodetach\x00--debug\x00",
		"/usr/sbin/tayga\x00--config\x00/etc/translator46.conf\x00",
	} {
		if matchingArgs([]byte(args), *s.settings.NAT46) {
			t.Fatal("ambiguous instance arguments accepted")
		}
	}
	duplicate := observer{run: func(context.Context, []string, time.Duration, int) ([]byte, error) {
		return []byte("ActiveState=\nActiveState=active\nSubState=running\nMainPID=123\nInvocationID=" + strings.Repeat("a", 32)), nil
	}}
	if _, err := duplicate.service(context.Background(), s.settings, *s.settings.NAT46); err == nil {
		t.Fatal("duplicate service property accepted")
	}
}

func TestTranslationReadinessExpiresWithoutRenewingNativeRecords(t *testing.T) {
	s := fixture(t)
	now := catalog.Now()
	native := []catalog.Record{
		{ID: "v4", Name: "ipv4.local.", Type: "A", Data: "192.0.2.42", Source: "lan-a", Expires: now.Wall.Add(30 * time.Second)},
		{ID: "v6", Name: "ipv6.local.", Type: "AAAA", Data: "2001:db8:1::42", Source: "lan-a", Expires: now.Wall.Add(30 * time.Second)},
	}
	value := readiness{observed: now, nat64: true, generation: 42, maps: map[netip.Addr]netip.Addr{netip.MustParseAddr("2001:db8:1::42"): netip.MustParseAddr("198.51.100.42")}}
	s.current.Store(&value)
	for _, offset := range []time.Duration{0, 8 * time.Second, 10 * time.Second} {
		moment := catalog.Moment{Wall: now.Wall.Add(offset), Mono: now.Mono + offset}
		records := s.Render(native, moment)
		expected := 4
		if offset >= lease {
			expected = 2
		}
		if len(records) != expected || !reflect.DeepEqual(records[:2], native) {
			t.Fatal("native or translated records changed unexpectedly", offset, records)
		}
		for _, r := range records[2:] {
			if !r.Expires.Equal(now.Wall.Add(lease)) {
				t.Fatal("read renewed translator deadline", r)
			}
		}
	}
	for _, moment := range []catalog.Moment{
		{Wall: now.Wall, Mono: now.Mono - time.Second}, {Wall: now.Wall.Add(20 * time.Second), Mono: now.Mono + time.Second},
	} {
		if !reflect.DeepEqual(s.Render(native, moment), native) {
			t.Fatal("clock failure kept translation")
		}
	}
	value.maps = nil
	s.current.Store(&value)
	if len(s.Render(native, now)) != 3 {
		t.Fatal("NAT46 allocated a missing mapping")
	}
	value.nat64 = false
	s.current.Store(&value)
	if !reflect.DeepEqual(s.Render(native, now), native) {
		t.Fatal("failed translation withdrew native records")
	}
	var disabled *Sampler
	if !reflect.DeepEqual(disabled.Render(native, now), native) {
		t.Fatal("disabled translation changed native records")
	}
}

func TestImmutableReaderRejectsMutableSymlinkAndFIFO(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "profile")
	if err := os.WriteFile(path, []byte(config46), 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := immutableConfig(path); err == nil {
		t.Fatal("writable filesystem attested as immutable")
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := immutableConfig(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0400); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := immutableConfig(fifo); err == nil || time.Since(started) > time.Second {
		t.Fatal("FIFO accepted or blocked readiness")
	}
}

func TestSamplerCancelsAndClearsReadiness(t *testing.T) {
	s := fixture(t)
	x := scriptedObserver(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for s.current.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.current.Load() == nil {
		cancel()
		<-done
		t.Fatal("sampler never published")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sampler survived cancellation")
	}
	if s.current.Load() != nil || len(x.calls) != 7 {
		t.Fatal("sampler did not clear or made unexpected calls", len(x.calls))
	}
}
