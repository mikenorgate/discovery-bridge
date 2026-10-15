//go:build integration && linux

package discoverydns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func integrationBinary(t *testing.T, variable, name string) string {
	t.Helper()
	if value := os.Getenv(variable); value != "" {
		return value
	}
	value, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("real %s qualification requires %s or the binary in PATH", name, variable)
	}
	return value
}

func startDNSProcess(t *testing.T, binary, contents, filename string, port int, args ...string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, filename)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(directory, "process-output"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	args = append(args, path)
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-finished
		if err := log.Close(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			data, err := os.ReadFile(log.Name())
			if err == nil {
				t.Logf("%s: %s", filepath.Base(binary), data)
			}
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-timer.C:
			t.Fatal("resolver did not start")
		case <-ticker.C:
		}
	}
}

func TestRealUnboundDNS64AndColdCoreDNS(t *testing.T) {
	unbound := integrationBinary(t, "UNBOUND_TEST_BINARY", "unbound")
	syntheticReverse, err := dnswire.ReverseZone(netip.MustParsePrefix("fd00:64::/96"))
	if err != nil {
		t.Fatal(err)
	}
	front, private, recursive := freePort(t), freePort(t), freePort(t)
	settings := testSettings()
	settings.Listeners = []config.Endpoint{{Host: "127.0.0.1", Port: front}}
	var afterMetadataQueries atomic.Int64
	var structuralQueries atomic.Int64
	h := testHandler(t, settings, func(ctx context.Context, question native.Question) (native.Result, error) {
		if question.DNS.Name == "after-metadata.local." {
			afterMetadataQueries.Add(1)
		}
		if question.DNS.Name == "_tcp.local." {
			structuralQueries.Add(1)
		}
		if os.Getenv("DISCOVERY_DNS_TEST_TRACE") == "1" {
			t.Logf("native query %s %s at %s", question.DNS.Name, dns.TypeToString[question.DNS.Qtype], time.Now().Format(time.RFC3339Nano))
		}
		result := native.Result{Epoch: "one"}
		switch question.DNS.Name {
		case "v4.local.":
			result.Records = testRRs(t, "v4.local. 120 IN A 192.0.2.10")
		case "dual.local.":
			result.Records = testRRs(t, "dual.local. 120 IN A 192.0.2.11", "dual.local. 120 IN AAAA 2001:db8:1::11")
		case "10.2.0.192.in-addr.arpa.":
			result.Records = testRRs(t, "10.2.0.192.in-addr.arpa. 120 IN PTR v4.local.")
		case "_http._tcp.local.":
			result.Records = testRRs(t,
				"_http._tcp.local. 120 IN PTR Lamp._http._tcp.local.",
				"Lamp._http._tcp.local. 120 IN SRV 0 0 80 v4.local.",
				"Lamp._http._tcp.local. 120 IN TXT \"path=/\"",
				"v4.local. 120 IN A 192.0.2.10",
			)
		default:
			timer := time.NewTimer(6 * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return native.Result{}, ctx.Err()
			case <-timer.C:
			}
			if strings.HasPrefix(question.DNS.Name, "delayed") {
				result.Records = testRRs(t, question.DNS.Name+" 120 IN A 192.0.2.20")
			}
		}
		return result, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() { finished <- h.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	base := `server:
 interface: 127.0.0.1
 port: %d
 username: ""
 chroot: ""
 directory: ""
 pidfile: ""
 use-syslog: no
 do-daemonize: no
 verbosity: 1
 do-not-query-localhost: no
 access-control: 127.0.0.1/32 allow
 module-config: "dns64 iterator"
 dns64-prefix: %s
 dns64-synthall: no
 cache-min-ttl: 0
 serve-expired: no
 tcp-auth-query-timeout: %d
 infra-cache-min-rtt: 500
 tcp-reuse-timeout: 30000
 discard-timeout: 30000
 local-zone: "alpha.devices.example.test." transparent
 local-zone: "2.0.192.in-addr.arpa." transparent
 local-zone: "%s" transparent
 local-data: ". 10 IN NS ns.example.test."
`
	privateConfig := fmt.Sprintf(base, private, "fd00:64::/96", 8000, syntheticReverse) + " qname-minimisation: no\n"
	for _, zone := range []string{"alpha.devices.example.test.", "2.0.192.in-addr.arpa."} {
		privateConfig += fmt.Sprintf("stub-zone:\n name: %q\n stub-addr: 127.0.0.1@%d\n stub-first: no\n stub-prime: no\n stub-tcp-upstream: yes\n", zone, front)
	}
	startDNSProcess(t, unbound, privateConfig, "private.conf", private, "-d", "-c")
	mainConfig := fmt.Sprintf(base, recursive, "64:ff9b::/96", 30000, syntheticReverse)
	for _, zone := range []string{"alpha.devices.example.test.", "2.0.192.in-addr.arpa.", syntheticReverse} {
		mainConfig += fmt.Sprintf("forward-zone:\n name: %q\n forward-addr: 127.0.0.1@%d\n forward-first: no\n forward-tcp-upstream: yes\n", zone, private)
	}
	startDNSProcess(t, unbound, mainConfig, "recursive.conf", recursive, "-d", "-c")
	exchange := func(t *testing.T, port int, name string, kind uint16) *dns.Msg {
		t.Helper()
		request := new(dns.Msg)
		request.SetQuestion(name, kind)
		client := &dns.Client{Timeout: 35 * time.Second}
		reply, _, err := client.ExchangeContext(t.Context(), request, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("%s %s: %v", name, dns.TypeToString[kind], err)
		}
		if reply.Rcode != dns.RcodeSuccess {
			t.Fatal(reply)
		}
		for _, record := range reply.Answer {
			if record.Header().Ttl > 10 {
				t.Fatal("cache exceeded discovery lifetime", reply)
			}
		}
		return reply
	}
	t.Run("service discovery avoids structural address probes", func(t *testing.T) {
		reply := exchange(t, recursive, "_http._tcp.alpha.devices.example.test.", dns.TypePTR)
		if len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypePTR {
			t.Fatal("service discovery did not return its PTR:", reply)
		}
		if got := structuralQueries.Load(); got != 0 {
			t.Fatalf("service discovery generated %d unnecessary _tcp address lookups", got)
		}
	})
	t.Run("dns64 and native ipv6", func(t *testing.T) {
		for _, test := range []struct{ name, address string }{
			{"v4", "fd00:64::c000:20a"}, {"dual", "2001:db8:1::11"},
		} {
			reply := exchange(t, recursive, test.name+".alpha.devices.example.test.", dns.TypeAAAA)
			if len(reply.Answer) != 1 || !strings.Contains(reply.Answer[0].String(), test.address) {
				t.Fatal(reply)
			}
		}
	})
	t.Run("synthetic ptr", func(t *testing.T) {
		reverse, err := dns.ReverseAddr("fd00:64::c000:20a")
		if err != nil {
			t.Fatal(err)
		}
		reply := exchange(t, recursive, reverse, dns.TypePTR)
		if len(reply.Answer) == 0 || !strings.Contains(reply.String(), "v4.alpha.devices.example.test.") {
			t.Fatal(reply)
		}
	})
	t.Run("cold absence through unbound", func(t *testing.T) {
		for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
			began := time.Now()
			reply := exchange(t, recursive, strings.ToLower(dns.TypeToString[kind])+"-absent.alpha.devices.example.test.", kind)
			if len(reply.Answer) != 0 || len(reply.Ns) != 1 || time.Since(began) < 5*time.Second {
				t.Fatal("cold absence was not preserved", reply)
			}
		}
	})
	t.Run("cold after fast metadata", func(t *testing.T) {
		exchange(t, private, "alpha.devices.example.test.", dns.TypeSOA)
		exchange(t, recursive, "alpha.devices.example.test.", dns.TypeSOA)
		// Exercise a normal reconnect with the metadata RTT still cached.
		// Real Unbound owns this idle timer, so virtual test time cannot advance it.
		time.Sleep(31 * time.Second)
		began := time.Now()
		reply := exchange(t, recursive, "after-metadata.alpha.devices.example.test.", dns.TypeA)
		if len(reply.Answer) != 0 || len(reply.Ns) != 1 || time.Since(began) < 5*time.Second {
			t.Fatal("fast metadata shortened the cold-query budget", reply)
		}
		if got := afterMetadataQueries.Load(); got != 1 {
			t.Fatalf("cold lookup retried before its query budget: got %d native queries, want 1", got)
		}
	})
	t.Run("existing coredns forward cold replies", func(t *testing.T) {
		coredns := integrationBinary(t, "COREDNS_TEST_BINARY", "coredns")
		port := freePort(t)
		options := os.Getenv("COREDNS_TEST_FORWARD_OPTIONS")
		corefile := fmt.Sprintf(".:%d {\n bind 127.0.0.1\n timeouts {\n write 35s\n }\n forward . 127.0.0.1:%d {\n%s\n }\n}\n", port, recursive, options)
		startDNSProcess(t, coredns, corefile, "Corefile", port, "-conf")
		for _, name := range []string{"delayed", "absent", "ipv6-absent"} {
			began := time.Now()
			kind := dns.TypeA
			if name == "ipv6-absent" {
				kind = dns.TypeAAAA
			}
			reply := exchange(t, port, name+".alpha.devices.example.test.", kind)
			if time.Since(began) < 5*time.Second || (name == "delayed") != (len(reply.Answer) == 1) {
				t.Fatal("cold answer lost or not qualified", reply)
			}
		}
	})
}
