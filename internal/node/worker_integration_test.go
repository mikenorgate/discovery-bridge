//go:build integration && linux

package node

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		flags := flag.NewFlagSet("worker", flag.ExitOnError)
		fd, parent := flags.Int("control-fd", -1, ""), flags.Int("parent", -1, "")
		if err := flags.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		if err := RunWorker(context.Background(), *fd, *parent); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func podNamespace(t *testing.T, ctx context.Context) (*linuxnet.Namespace, int) {
	t.Helper()
	child := exec.CommandContext(ctx, "unshare", "--net", "sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	var ns *linuxnet.Namespace
	deadline := time.Now().Add(2 * time.Second)
	for {
		var err error
		ns, err = linuxnet.Open("/proc", child.Process.Pid)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() { _ = ns.Close() })
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "dummy0", "type", "dummy"}, {"link", "set", "dummy0", "up", "multicast", "on"}, {"address", "add", "198.51.100.42/24", "dev", "dummy0"}, {"address", "add", "2001:db8:2::42/64", "dev", "dummy0", "nodad"}} {
		command := exec.CommandContext(ctx, "nsenter", "--target", strconv.Itoa(child.Process.Pid), "--net", "ip")
		command.Args = append(command.Args, args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("namespace setup: %v: %s", err, output)
		}
	}
	return ns, child.Process.Pid
}

func workerExecutable(t *testing.T) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp("/tmp", "discovery-bridge-node-*.test")
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	_, copyErr := io.Copy(file, source)
	if err := errors.Join(copyErr, file.Chmod(0755), file.Close(), source.Close()); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

func TestUnprivilegedWorkerAnswersAndExpiresPodLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	ns, _ := podNamespace(t, ctx)
	addresses := []netip.Addr{netip.MustParseAddr("198.51.100.42"), netip.MustParseAddr("2001:db8:2::42")}
	details, err := ns.Inspect("dummy0", addresses)
	if err != nil {
		t.Fatal(err)
	}
	settings := config.Worker{Sources: map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, Forbidden: []string{}}
	p, err := policy.New(settings.Sources, settings.Forbidden)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := gateway.NewFeed(ctx, p, filepath.Join(t.TempDir(), "generation.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = feed.Close() })
	rr, err := dns.NewRR("sensor.local. 20 IN AAAA 2001:db8:1::43")
	if err != nil {
		t.Fatal(err)
	}
	now := catalog.Now()
	if err := feed.Publish([]catalog.Answer{{RR: rr, Source: "lan-a"}}, now.Wall, now); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	settings.Gateway = config.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	apiCtx, stopAPI := context.WithCancel(ctx)
	apiDone := make(chan error, 1)
	go func() {
		apiDone <- gateway.Serve(apiCtx, listener, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, gateway.CatalogAPI(feed, nil))
	}()
	t.Cleanup(func() { stopAPI(); <-apiDone })
	worker, err := linuxnet.StartWorker(ctx, workerExecutable(t), nil, 65532, 65532, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := worker.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-worker.Done:
		case <-time.After(time.Second):
			t.Error("worker did not exit")
		}
	})
	if err := linuxnet.Send(int(worker.Channel.Fd()), settings, nil); err != nil {
		t.Fatal(err)
	}
	// Each family uses real namespace sockets passed to the unprivileged process.
	for _, family := range []int{4, 6} {
		file, err := ns.Socket("dummy0", family)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = linuxnet.Revoke(file) })
		deadline := catalog.Now().Mono + 3*time.Second
		description := linuxnet.Description{Index: details.Index, Family: family, Addresses: addresses}
		uid := fmt.Sprintf("pod-%d", family)
		if err := linuxnet.Send(int(worker.Channel.Fd()), map[string]any{"op": "open", "uid": uid, "token": "0123456789abcdef0123456789abcdef", "deadline": deadline.Seconds(), "sockets": []linuxnet.Description{description}}, []int{int(file.Fd())}); err != nil {
			t.Fatal(err)
		}
		clientFile, err := ns.Socket("dummy0", family)
		if err != nil {
			t.Fatal(err)
		}
		client, err := linuxnet.Adopt(clientFile, description)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		group := unix.Sockaddr(&unix.SockaddrInet4{Port: 5353, Addr: [4]byte{224, 0, 0, 251}})
		control := (&ipv4.ControlMessage{Src: net.IP(addresses[0].AsSlice()), IfIndex: details.Index}).Marshal()
		if family == 6 {
			group = &unix.SockaddrInet6{Port: 5353, ZoneId: uint32(details.Index), Addr: netip.MustParseAddr("ff02::fb").As16()}
			control = (&ipv6.ControlMessage{Src: net.IP(addresses[1].AsSlice()), IfIndex: details.Index}).Marshal()
		}
		query := dns.Msg{Question: []dns.Question{{Name: "sensor.local.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}}
		wire, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		send := func() {
			t.Helper()
			if _, err := unix.SendmsgN(int(file.Fd()), wire, control, group, 0); err != nil {
				t.Fatal(err)
			}
		}
		// Allow the initial HTTP refresh to complete, then send a local query.
		time.Sleep(100 * time.Millisecond)
		send()
		if err := client.Socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		for {
			packet, _, err := client.Receive()
			if err != nil {
				t.Fatal("pod answer missing", family, err)
			}
			message, err := responderMessage(packet)
			if err != nil {
				t.Fatal(err)
			}
			if !message.Response {
				if string(packet) != string(wire) {
					t.Fatal("worker sent an unexpected question into the pod", message)
				}
				continue
			}
			if len(message.Answer) != 1 || message.Answer[0].Header().Name != "sensor.local." || message.Answer[0].Header().Ttl < 1 || message.Answer[0].Header().Ttl > 2 {
				t.Fatal("answer did not preserve name or eligibility TTL", message)
			}
			if address, ok := message.Answer[0].(*dns.AAAA); !ok || !address.AAAA.Equal(net.ParseIP("2001:db8:1::43")) {
				t.Fatal("native device address changed", message)
			}
			break
		}
		if family == 4 {
			if err := linuxnet.Send(int(worker.Channel.Fd()), map[string]string{"op": "remove", "uid": uid, "token": "0123456789abcdef0123456789abcdef"}, nil); err != nil {
				t.Fatal(err)
			}
		} else {
			// Broker heartbeats keep the process alive but cannot renew eligibility.
			for catalog.Now().Mono < deadline {
				if err := linuxnet.Send(int(worker.Channel.Fd()), map[string]string{"op": "ping"}, nil); err != nil {
					t.Fatal(err)
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
		if err := linuxnet.Send(int(worker.Channel.Fd()), map[string]string{"op": "ping"}, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		send()
		if err := client.Socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		for {
			packet, _, err := client.Receive()
			if err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					break
				}
				t.Fatal(err)
			}
			message, err := responderMessage(packet)
			if err != nil {
				t.Fatal(err)
			}
			for _, rr := range append(message.Answer, message.Extra...) {
				if rr.Header().Ttl != 0 {
					t.Fatal("withdrawn or expired pod still received live answers", message)
				}
			}
			if !message.Response && string(packet) != string(wire) {
				t.Fatal("withdrawn or expired pod still received answers", message, err)
			}
		}
		select {
		case err := <-worker.Done:
			t.Fatal("worker exited during per-pod withdrawal", err)
		default:
		}
	}
}

func responderMessage(wire []byte) (*dns.Msg, error) {
	message := new(dns.Msg)
	err := message.Unpack(wire)
	return message, err
}

func TestBrokerVerifiesSandboxAndRevokesWithdrawnSockets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	_, pid := podNamespace(t, ctx)
	settings := testSettings(t)
	settings.PodInterface = "dummy0"
	raw := strings.Replace(selectedPod, `"2001:db8:1::42"`, `"2001:db8:2::42"},{"ip":"198.51.100.42"`, 1)
	id := strings.Repeat("a", 64)
	status := fmt.Sprintf(`{"status":{"id":%q,"state":"SANDBOX_READY","metadata":{"uid":"pod-1","name":"automation","namespace":"apps"},"network":{"ip":"2001:db8:2::42","additionalIps":[{"ip":"198.51.100.42"}]},"linux":{"namespaces":{"options":{"network":"POD"}}}},"info":{"pid":%d,"processStatus":"running","netNamespaceClosed":false}}`, id, pid)
	inspections := 0
	read := func(_ context.Context, argv []string) (json.RawMessage, error) {
		if argv[len(argv)-1] == id {
			inspections++
			return []byte(status), nil
		}
		return []byte(`{"items":[{"id":"` + id + `","metadata":{"uid":"pod-1"}}]}`), nil
	}
	broker, err := NewBroker(settings, read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	if err := broker.Reconcile(ctx, []json.RawMessage{[]byte(raw)}, catalog.Now().Mono); err != nil {
		t.Fatal(err)
	}
	l := broker.leases["pod-1"]
	if l == nil || inspections != 2 || len(l.sockets) != 2 {
		t.Fatal("sandbox was not independently verified twice", l, inspections)
	}
	duplicate, err := unix.FcntlInt(l.sockets[0].Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := linuxnet.Adopt(os.NewFile(uintptr(duplicate), "worker duplicate"), l.descriptions[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	if err := broker.Reconcile(ctx, []json.RawMessage{}, catalog.Now().Mono); err != nil || len(broker.leases) != 0 {
		t.Fatal("API removal did not revoke eligibility", err)
	}
	wire := claimPacket(t, true, "sensor.local. 10 IN A 192.0.2.43")
	if err := endpoint.Send(wire, &net.UDPAddr{IP: net.ParseIP("198.51.100.42"), Port: 5353}, true); err == nil {
		t.Fatal("broker withdrawal left worker duplicate usable")
	}
}
