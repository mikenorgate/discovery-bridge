package services

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
)

func serve(t *testing.T, handler gateway.Handler, admitted string) (*gateway.Client, context.Context) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- gateway.Serve(ctx, listener, []netip.Prefix{netip.MustParsePrefix(admitted)}, handler) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	client, err := gateway.NewClient(config.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port})
	if err != nil {
		t.Fatal(err)
	}
	return client, ctx
}

func TestOnlyAdmittedPublicationListenerCanReplaceIntents(t *testing.T) {
	r, err := NewReceiver("kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	client, ctx := serve(t, r.API(), "127.0.0.1/32")
	now := catalog.Now()
	data := payload(t, now.Wall, []Intent{readyIntent(t)})
	if _, err := client.Post(ctx, "/v1/publications", data, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"/v1/catalog", "/v1/lookup"} {
		if _, err := client.Post(ctx, operation, data, http.StatusNotFound); err != nil {
			t.Fatal("publication listener exposed a node operation", err)
		}
	}
	unapproved, ctx := serve(t, r.API(), "192.0.2.0/24")
	if _, err := unapproved.Post(ctx, "/v1/publications", payload(t, now.Wall.Add(time.Second), []Intent{}), http.StatusOK); err == nil {
		t.Fatal("unapproved source replaced Service records")
	}
	if len(r.Records(catalog.Now())) != 6 {
		t.Fatal("rejected producer changed admitted state")
	}
	nodes, ctx := serve(t, gateway.CatalogAPI(nil, nil), "127.0.0.1/32")
	if _, err := nodes.Post(ctx, "/v1/publications", data, http.StatusNotFound); err != nil {
		t.Fatal("node listener exposed publication", err)
	}
	// Retransmissions are rate-limited without extending their original lease.
	api := r.API()
	for i := range 5 {
		status, _ := api(ctx, http.MethodPost, "/v1/publications", data)
		want := http.StatusOK
		if i == 4 {
			want = http.StatusTooManyRequests
		}
		if status != want {
			t.Fatal("publication request budget changed", i, status)
		}
	}
	if len(r.Records(catalog.Moment{Wall: now.Wall.Add(Lease), Mono: now.Mono + Lease})) != 0 {
		t.Fatal("HTTP replay renewed the producer lease")
	}
}
