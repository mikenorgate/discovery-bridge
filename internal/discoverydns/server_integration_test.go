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

func startTestDNS(t *testing.T, query queryFunc) (string, context.CancelFunc) {
	t.Helper()
	port := freePort(t)
	settings := testSettings()
	settings.Listeners = []config.Endpoint{{Host: "127.0.0.1", Port: port}}
	h := testHandler(t, settings, query)
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() { finished <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{}).DialContext(ready, "tcp", address)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			return address, cancel
		}
		select {
		case <-ready.Done():
			t.Fatal("DNS listener did not start")
		case <-ticker.C:
		}
	}
}

func TestTCPPipelineDoesNotBlockAvailableAnswers(t *testing.T) {
	for _, test := range []struct {
		name, owner string
		kind        uint16
	}{
		{name: "zone metadata", owner: "alpha.devices.example.test.", kind: dns.TypeSOA},
		{name: "cached address", owner: "ready.alpha.devices.example.test.", kind: dns.TypeA},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			records := testRRs(t, "ready.local. 120 IN A 192.0.2.10")
			address, _ := startTestDNS(t, func(ctx context.Context, question native.Question) (native.Result, error) {
				if question.DNS.Name != "slow.local." {
					return native.Result{Epoch: "one", Records: records}, nil
				}
				close(entered)
				select {
				case <-ctx.Done():
					return native.Result{}, ctx.Err()
				case <-release:
					return native.Result{Epoch: "one"}, nil
				}
			})
			conn, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Dial(address)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			request := new(dns.Msg)
			request.SetQuestion("slow.alpha.devices.example.test.", dns.TypeA)
			request.Id = 1
			if err := conn.WriteMsg(request); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("slow lookup did not start")
			}
			request.SetQuestion(test.owner, test.kind)
			request.Id = 2
			if err := conn.WriteMsg(request); err != nil {
				t.Fatal(err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			reply, err := conn.ReadMsg()
			if err != nil {
				t.Fatal("available answer blocked behind unresolved query:", err)
			}
			if reply.Id != 2 || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
				t.Fatal("wrong pipelined reply:", reply)
			}
			close(release)
			reply, err = conn.ReadMsg()
			if err != nil || reply.Id != 1 || reply.Rcode != dns.RcodeSuccess {
				t.Fatal("unresolved query lost its own reply:", reply, err)
			}
		})
	}
}

func TestTCPDisconnectCancelsLookup(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	address, _ := startTestDNS(t, func(ctx context.Context, _ native.Question) (native.Result, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return native.Result{}, ctx.Err()
	})
	conn, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	request := new(dns.Msg)
	request.SetQuestion("slow.alpha.devices.example.test.", dns.TypeA)
	if err := conn.WriteMsg(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("disconnected client retained its lookup")
	}
}

func TestTCPInFlightLimitAndCancellation(t *testing.T) {
	entered := make(chan struct{}, maxTCPInFlight)
	cancelled := make(chan struct{}, maxTCPInFlight)
	address, _ := startTestDNS(t, func(ctx context.Context, _ native.Question) (native.Result, error) {
		entered <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return native.Result{}, ctx.Err()
	})
	conn, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for index := range maxTCPInFlight {
		request := new(dns.Msg)
		request.SetQuestion("slow"+strconv.Itoa(index)+".alpha.devices.example.test.", dns.TypeA)
		request.Id = uint16(index)
		if err := conn.WriteMsg(request); err != nil {
			t.Fatal(err)
		}
	}
	for range maxTCPInFlight {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("admitted lookup did not start")
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("alpha.devices.example.test.", dns.TypeSOA)
	request.Id = 100
	if err := conn.WriteMsg(request); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.ReadMsg()
	if err != nil || reply.Id != request.Id || reply.Rcode != dns.RcodeServerFailure {
		t.Fatal("excess query was not rejected promptly:", reply, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range maxTCPInFlight {
		select {
		case <-cancelled:
		case <-time.After(time.Second):
			t.Fatal("disconnect left an admitted lookup running")
		}
	}
}

func TestTCPShutdownCancelsLookup(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	address, stop := startTestDNS(t, func(ctx context.Context, _ native.Question) (native.Result, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return native.Result{}, ctx.Err()
	})
	conn, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	request := new(dns.Msg)
	request.SetQuestion("slow.alpha.devices.example.test.", dns.TypeA)
	if err := conn.WriteMsg(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	stop()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("server shutdown did not cancel lookup")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ReadMsg(); err == nil {
		t.Fatal("shutdown retained the TCP connection")
	}
}

func TestTCPRequestLimitDrainsReplies(t *testing.T) {
	address, _ := startTestDNS(t, func(context.Context, native.Question) (native.Result, error) {
		return native.Result{}, errors.New("metadata must not query the LAN")
	})
	conn, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for index := range maxTCPRequests {
		request := new(dns.Msg)
		request.SetQuestion("alpha.devices.example.test.", dns.TypeSOA)
		request.Id = uint16(index)
		if err := conn.WriteMsg(request); err != nil {
			t.Fatal(err)
		}
		reply, err := conn.ReadMsg()
		if err != nil || reply.Id != request.Id || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
			t.Fatal("request-limit drain lost an admitted reply:", reply, err)
		}
	}
	if _, err := conn.ReadMsg(); err == nil {
		t.Fatal("request-limited connection remained open")
	}
}
