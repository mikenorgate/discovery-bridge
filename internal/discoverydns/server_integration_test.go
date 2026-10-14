//go:build integration && linux

package discoverydns

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

func TestUDPTruncationEDNSAndTCP(t *testing.T) {
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	settings := testSettings()
	settings.Listeners = []config.Endpoint{{Host: "127.0.0.1", Port: port}}
	data := strings.Repeat("x", 220)
	records := testRRs(t,
		"large.local. 120 IN TXT \"a="+data+"\"",
		"large.local. 120 IN TXT \"b="+data+"\"",
		"large.local. 120 IN TXT \"c="+data+"\"",
		"large.local. 120 IN TXT \"d="+data+"\"",
	)
	h := testHandler(t, settings, func(context.Context, native.Question) (native.Result, error) {
		return native.Result{Epoch: "one", Records: records}, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	ready, stopReady := context.WithTimeout(ctx, 3*time.Second)
	defer stopReady()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{}).DialContext(ready, "tcp", address)
		if err == nil {
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			break
		}
		select {
		case <-ready.Done():
			t.Fatal("DNS listener did not start")
		case <-ticker.C:
		}
	}
	for _, test := range []struct {
		name, network string
		edns          uint16
		truncated     bool
	}{
		{name: "udp without edns", network: "udp", truncated: true},
		{name: "udp with edns", network: "udp", edns: 1232},
		{name: "tcp full answer", network: "tcp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion("large.alpha.devices.example.test.", dns.TypeTXT)
			if test.edns != 0 {
				request.SetEdns0(test.edns, false)
			}
			client := &dns.Client{Net: test.network, Timeout: 2 * time.Second, UDPSize: 1232}
			reply, _, err := client.ExchangeContext(ctx, request, address)
			if err != nil {
				t.Fatal(err)
			}
			if reply.Truncated != test.truncated || !test.truncated && len(reply.Answer) != 4 || reply.Rcode != dns.RcodeSuccess {
				t.Fatal(reply)
			}
		})
	}
}
