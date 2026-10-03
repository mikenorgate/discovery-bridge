//go:build integration

package avahi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

func privateBus(t *testing.T) string {
	path, _ := privateBusProcess(t)
	return path
}

func TestStartupWaitsForAvahiInitializationAndHonorsDeadline(t *testing.T) {
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	var calls atomic.Int32
	var state atomic.Int32
	state.Store(1)
	if err := f.conn.ExportMethodTable(map[string]any{"GetState": func() (int32, *dbus.Error) {
		if calls.Add(1) == 3 {
			state.Store(2)
		}
		return state.Load(), nil
	}}, "/", server); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := connectBus(ctx, path)
	if err != nil || calls.Load() != 3 {
		t.Fatal("initializing Avahi did not get a fresh running epoch", err, calls.Load())
	}
	b.close()
	state.Store(1)
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if _, err := connectBus(short, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("startup ignored its deadline", err)
	}
	state.Store(4) // Failure is permanent; it must not be retried as initialization.
	before := calls.Load()
	if _, err := connectBus(ctx, path); err == nil || calls.Load() != before+1 {
		t.Fatal("failed Avahi was retried or accepted", err, calls.Load()-before)
	}
}

func privateBusProcess(t *testing.T) (string, *exec.Cmd) {
	t.Helper()
	program, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Fatal("integration test needs dbus-daemon", err)
	}
	dir, err := os.MkdirTemp("", "db-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "bus")
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, program, "--session", "--nofork", "--nopidfile", "--address=unix:path="+path, "--print-address=1")
	command.WaitDelay = time.Second
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case value := <-ready:
		if !strings.HasPrefix(value, "unix:path="+path) {
			t.Fatal("private D-Bus startup failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("private D-Bus startup timed out")
	}
	return path, command
}

type fakeAvahi struct {
	conn    *dbus.Conn
	mu      sync.Mutex
	queries []Query
	records map[Query]dns.RR
	freed   []dbus.ObjectPath
}

func avahiFixture(t *testing.T, path string, records map[Query]dns.RR) *fakeAvahi {
	t.Helper()
	conn, err := dbus.Connect("unix:path=" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f := &fakeAvahi{conn: conn, records: records}
	if err := conn.ExportMethodTable(map[string]any{"GetState": func() (int32, *dbus.Error) { return 2, nil }}, "/", server); err != nil {
		t.Fatal(err)
	}
	if err := conn.ExportMethodTable(map[string]any{"RecordBrowserPrepare": f.prepare}, "/", server2); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(service, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return f
}

func (f *fakeAvahi) prepare(index, protocol int32, name string, class, kind uint16, flags uint32) (dbus.ObjectPath, *dbus.Error) {
	if index != 2 || (protocol != 0 && protocol != 1) || class != dns.ClassINET || flags != 2 {
		return "", dbus.MakeFailedError(fmt.Errorf("invalid scoped browser request"))
	}
	family := 4
	if protocol == 1 {
		family = 6
	}
	query := Query{int(index), family, catalog.NameKey(name), kind}
	f.mu.Lock()
	f.queries = append(f.queries, query)
	path := dbus.ObjectPath(fmt.Sprintf("/browser/%d", len(f.queries)))
	f.mu.Unlock()
	err := f.conn.ExportMethodTable(map[string]any{
		"Start": func() *dbus.Error {
			if rr := f.records[query]; rr != nil {
				raw, err := rdata(rr)
				if err != nil {
					return dbus.MakeFailedError(err)
				}
				// Send before the Start reply to exercise prepare-before-start routing.
				if err := f.conn.Emit(path, browserInterface+".ItemNew", index, protocol, rr.Header().Name, class, kind, raw, uint32(5)); err != nil {
					return dbus.MakeFailedError(err)
				}
			}
			return nil
		},
		"Free": func() *dbus.Error {
			f.mu.Lock()
			f.freed = append(f.freed, path)
			f.mu.Unlock()
			return nil
		},
	}, path, browserInterface)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return path, nil
}

func TestRealDBusBrowsingCorrelatesWireAndExpires(t *testing.T) {
	path := privateBus(t)
	var wireRecords []dns.RR
	fixture := make(map[Query]dns.RR)
	for _, text := range []string{
		catalog.Enumeration + " 6 IN PTR _example._tcp.local.",
		`_example._tcp.local. 6 IN PTR Office\032Printer._example._tcp.local.`,
		`Office\032Printer._example._tcp.local. 6 IN SRV 0 0 1234 host.local.`,
		`Office\032Printer._example._tcp.local. 6 IN TXT "binary=\000\255"`,
		"host.local. 6 IN A 192.0.2.42", "host.local. 6 IN AAAA 2001:db8:1::42",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		wireRecords = append(wireRecords, rr)
		fixture[Query{2, 4, catalog.NameKey(rr.Header().Name), rr.Header().Rrtype}] = rr
	}
	f := avahiFixture(t, path, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4, 6}}}
	b, err := ConnectBrowser(ctx, path, links)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Watch(ctx, Query{2, 4, "_EXAMPLE._tcp.local.", dns.TypePTR}); err != nil {
		t.Fatal(err)
	}
	cache := observation.New()
	for range len(fixture) {
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		event, err := b.Next(bounded)
		stop()
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.Hint(event.Epoch, event.Record, event.Added); err != nil {
			t.Fatal(err)
		}
		if err := b.Follow(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	now := catalog.Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("browser cache alone produced records", values, err)
	}
	scopes, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: wireRecords}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	packet := observation.Packet{Interface: 2, Generation: "link-a", Family: 4, Source: netip.MustParseAddr("192.0.2.42"), Destination: netip.MustParseAddr("224.0.0.251"), HopLimit: 255, SourcePort: 5353, DestinationPort: 5353, Wire: wire}
	observed, err := observation.Parse(packet, links, scopes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Ingest(observed, now.Mono); err != nil {
		t.Fatal(err)
	}
	values, err := cache.Records(now)
	if err != nil || len(values) != 6 {
		t.Fatal("scoped D-Bus and packet graph did not correlate", len(values), err)
	}
	for _, value := range values {
		if value.Expires.Sub(now.Wall) != 6*time.Second {
			t.Fatal("browser hint changed native TTL")
		}
	}
	now.Mono, now.Wall = 6*time.Second, now.Wall.Add(6*time.Second)
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("cached D-Bus hints renewed expired records", values, err)
	}
	if err := cache.Ingest(observed, now.Mono); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.ReleaseName(service); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if event, err := b.Next(bounded); err == nil || bounded.Err() != nil {
		t.Fatal("owner loss did not wake consumer", event, err)
	}
	cache.ForgetEpoch(b.Epoch())
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("Avahi owner loss retained authority", values, err)
	}
	if _, err := b.Watch(ctx, Query{2, 4, "host.local.", dns.TypeA}); err == nil {
		t.Fatal("failed epoch accepted new watch")
	}
}

func TestRealDBusRetirementPreservesLiveDependencies(t *testing.T) {
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	b, err := ConnectBrowser(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	serviceQuery := Query{2, 4, "example._example._tcp.local.", dns.TypeSRV}
	needed := Query{2, 4, "host.local.", dns.TypeAAAA}
	idle := Query{2, 4, "idle.local.", dns.TypeA}
	for _, query := range []Query{serviceQuery, needed, idle} {
		if _, err := b.Watch(context.Background(), query); err != nil {
			t.Fatal(err)
		}
	}
	rr, err := dns.NewRR("example._example._tcp.local. 0 IN SRV 0 0 1234 host.local.")
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	for query := range b.touched {
		b.touched[query] = time.Now().Add(-121 * time.Second)
	}
	servicePath, idlePath := b.queries[serviceQuery], b.queries[idle]
	b.seen[seenKey{servicePath, (catalog.Answer{RR: rr}).Key()}] = rr
	b.mu.Unlock()
	if err := b.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	_, retainedNeeded := b.queries[needed]
	_, retainedIdle := b.queries[idle]
	b.mu.Unlock()
	f.mu.Lock()
	freed := append([]dbus.ObjectPath(nil), f.freed...)
	f.mu.Unlock()
	if !retainedNeeded || retainedIdle || len(freed) != 1 || freed[0] != idlePath {
		t.Fatal("retirement lost active dependency", retainedNeeded, retainedIdle, freed)
	}
}

func TestStalledAuthenticationClosesSocketWithinDeadline(t *testing.T) {
	dir, err := os.MkdirTemp("", "db-stall-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "bus")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(closed)
			return
		}
		defer func() { _ = conn.Close(); close(closed) }()
		buffer := make([]byte, 64)
		for {
			if _, err := conn.Read(buffer); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	if _, err := connectBus(context.Background(), path); err == nil {
		t.Fatal("stalled authentication succeeded")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("authentication timeout leaked socket")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("authentication exceeded its deadline")
	}
}
