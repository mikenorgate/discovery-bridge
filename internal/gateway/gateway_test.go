package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
)

func testPolicy(t *testing.T) *policy.SourcePolicy {
	t.Helper()
	p, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startAPI(t *testing.T, handler Handler, clients []netip.Prefix) (config.Endpoint, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, clients, handler) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return config.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, ctx
}

func TestCatalogLookupAndImmediateWithdrawal(t *testing.T) {
	feed, err := NewFeed(context.Background(), testPolicy(t), filepath.Join(t.TempDir(), "generation.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := feed.Close(); err != nil {
			t.Error(err)
		}
	})
	rr, err := dns.NewRR("sensor.local. 20 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	now := catalog.Now()
	if err := feed.Publish([]catalog.Answer{{RR: rr, Source: "lan-a"}}, now.Wall, now); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	lookups := NewLookups(func(ctx context.Context, q responder.Question) error {
		if q.Name != "sensor.local." || q.Type != dns.TypeAAAA {
			t.Error(q)
		}
		calls.Add(1)
		return ctx.Err()
	})
	t.Cleanup(lookups.Close)
	endpoint, ctx := startAPI(t, CatalogAPI(feed, lookups), []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	client, err := NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	node := catalog.NewNodeFeed(testPolicy(t), nil)
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	if view := node.View(catalog.Now()); len(view) != 1 || view[0].Unique {
		t.Fatal("native pod hostname lost shared ownership", view)
	}
	value, err := (responder.Query{Questions: []responder.Question{{Name: "sensor.local.", Type: dns.TypeAAAA, Class: 1}}}).Lookup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Post(ctx, "/v1/lookup", data, 202); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("cooldown did not coalesce duplicate demand", calls.Load())
	}
	feed.Withdraw()
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	if len(node.View(catalog.Now())) != 0 {
		t.Fatal("withdrawn records survived HTTP refresh")
	}
	if _, err := client.Post(ctx, "/v1/publications", []byte(`{"schema":1}`), 200); err == nil {
		t.Fatal("node listener accepted publication")
	}
}

func TestSourceAdmissionAndHTTPFraming(t *testing.T) {
	var calls atomic.Int32
	handler := func(context.Context, string, string, []byte) (int, []byte) {
		calls.Add(1)
		return 200, []byte(`{"ok":true}`)
	}
	endpoint, ctx := startAPI(t, handler, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	client, err := NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Post(ctx, "/v1/catalog", []byte(`{"schema":1}`), 200); err == nil {
		t.Fatal("unapproved source reached handler")
	}
	if calls.Load() != 0 {
		t.Fatal("source admission happened after HTTP handling")
	}
	endpoint, _ = startAPI(t, handler, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	for _, headers := range []string{
		"Content-Length: 2\r\ncontent-length: 2\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Content-Length: 20000\r\n",
		"Content-Length: 2\r\nExpect: 100-continue\r\n",
	} {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err = io.WriteString(connection, "POST /v1/catalog HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\n"+headers+"\r\n{}")
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(connection).ReadString('\n')
		if err != nil || !strings.Contains(line, "400") {
			t.Fatal(line, err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed framing reached operation handler")
	}
}

func TestLookupCancellationDoesNotCancelSharedDemand(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	lookups := NewLookups(func(ctx context.Context, _ responder.Question) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	t.Cleanup(lookups.Close)
	data := []byte(`{"schema":1,"questions":[{"name":"sensor.local.","type":1,"class":1}]}`)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := lookups.Submit(ctx, data); first <- err }()
	<-started
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() { _, err := lookups.Submit(context.Background(), data); second <- err }()
	close(release)
	if err := <-second; err != nil {
		t.Fatal("disconnect cancelled coalesced LAN work", err)
	}
}
