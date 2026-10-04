//go:build integration && linux

package observation

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func networkLab(t *testing.T) (*linuxnet.Namespace, *linuxnet.Namespace, linuxnet.Interface, linuxnet.Interface) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("packet integration requires isolated root namespace privileges")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	var children []*exec.Cmd
	var namespaces []*linuxnet.Namespace
	for range 2 {
		child := exec.CommandContext(ctx, "unshare", "--net", "sleep", "60")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
		children = append(children, child)
		var ns *linuxnet.Namespace
		var err error
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			ns, err = linuxnet.Open("/proc", child.Process.Pid)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ns.Close(); err != nil {
				t.Error(err)
			}
		})
		namespaces = append(namespaces, ns)
	}
	run := func(which int, args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "nsenter", "--target", strconv.Itoa(children[which].Process.Pid), "--net", "ip")
		command.Args = append(command.Args, args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("packet lab setup: %v: %s", err, output)
		}
	}
	run(0, "link", "add", "lan0", "type", "veth", "peer", "name", "peer0")
	run(0, "link", "set", "peer0", "netns", strconv.Itoa(children[1].Process.Pid))
	for which, name := range []string{"lan0", "peer0"} {
		run(which, "link", "set", "lo", "up")
		run(which, "link", "set", name, "mtu", "1280", "up")
		address4, address6 := "192.0.2.1/24", "2001:db8:1::1/64"
		if which == 1 {
			address4, address6 = "192.0.2.42/24", "2001:db8:1::42/64"
		}
		run(which, "address", "add", address4, "dev", name)
		run(which, "address", "add", address6, "dev", name, "nodad")
	}
	inspect := func(which int, name string, addresses []netip.Addr) linuxnet.Interface {
		t.Helper()
		var result linuxnet.Interface
		var err error
		// Veth link-local addresses complete DAD independently of the nodad fixture.
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			result, err = namespaces[which].Inspect(name, addresses)
			if err == nil {
				return result
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal(err)
		return result
	}
	first := inspect(0, "lan0", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:1::1")})
	second := inspect(1, "peer0", []netip.Addr{netip.MustParseAddr("192.0.2.42"), netip.MustParseAddr("2001:db8:1::42")})
	return namespaces[0], namespaces[1], first, second
}

func TestRawReceiverLeavesUDPPortOwnershipAndReassemblesFullPackets(t *testing.T) {
	lan, peer, lanInterface, peerInterface := networkLab(t)
	for _, family := range []int{4, 6} {
		t.Run(strconv.Itoa(family), func(t *testing.T) {
			var receiver *Receiver
			var owner, producer *net.UDPConn
			address := "192.0.2.1"
			peerAddress, network := "192.0.2.42", "udp4"
			if family == 6 {
				address, peerAddress, network = "2001:db8:1::1", "2001:db8:1::42", "udp6"
			}
			if err := lan.With(func() error {
				var err error
				// An exclusive UDP listener stands in for Avahi's port ownership.
				owner, err = net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(address), Port: 5353})
				if err != nil {
					return err
				}
				receiver, err = OpenReceiver("lan0", lanInterface.Index, "link-a", family, lanInterface.Addresses)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
				if err := receiver.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := peer.With(func() error {
				var err error
				producer, err = net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(peerAddress), Port: 5353})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := producer.Close(); err != nil {
					t.Error(err)
				}
			}()
			raw, err := producer.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				if family == 4 {
					optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
				} else {
					optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT)
				}
			}); err != nil || optionErr != nil {
				t.Fatal(err, optionErr)
			}
			if family == 4 {
				if err := ipv4.NewPacketConn(producer).SetTTL(255); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := ipv6.NewPacketConn(producer).SetHopLimit(255); err != nil {
					t.Fatal(err)
				}
			}
			rr, err := dns.NewRR(`service._example._tcp.local. 6 IN TXT "binary=\000\255"`)
			if err != nil {
				t.Fatal(err)
			}
			for range 24 {
				rr.(*dns.TXT).Txt = append(rr.(*dns.TXT).Txt, strings.Repeat("x", 200))
			}
			message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{rr}}
			wire, err := message.Pack()
			if err != nil || len(wire) <= 1280 || len(wire) > 8952 {
				t.Fatal("fragmented fixture size", len(wire), err)
			}
			deadline := time.Now().Add(3 * time.Second)
			if err := receiver.Socket.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := owner.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if _, err := producer.WriteToUDP(wire, &net.UDPAddr{IP: net.ParseIP(address), Port: 5353}); err != nil {
				t.Fatal(err)
			}
			var packet Packet
			for {
				packet, err = receiver.Receive()
				if errors.Is(err, ErrPacketRejected) {
					continue
				}
				if err != nil {
					t.Fatal("full raw response", err)
				}
				if packet.SourcePort == 5353 && packet.DestinationPort == 5353 {
					break
				}
			}
			if packet.Interface != lanInterface.Index || packet.HopLimit != 255 || packet.Generation != "link-a" || packet.Source.String() != peerAddress || packet.Destination.String() != address || !bytes.Equal(packet.Wire, wire) {
				t.Fatal("raw receiver changed reassembled packet metadata", packet.Interface, packet.HopLimit, len(packet.Wire))
			}
			buffer := make([]byte, 9000)
			n, _, err := owner.ReadFromUDP(buffer)
			if err != nil || !bytes.Equal(buffer[:n], wire) {
				t.Fatal("raw receiver competed with Avahi's UDP port", n, err)
			}
			// A fresh question and explicit goodbye travel from the router as
			// source-port-5353 packets without a second UDP bind.
			var sender *Sender
			if err := lan.With(func() error {
				var err error
				sender, err = OpenSender("lan0", lanInterface.Index, family, lanInterface.Addresses)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := sender.Close(); err != nil {
					t.Error(err)
				}
			}()
			var observer *Receiver
			if err := peer.With(func() error {
				var err error
				observer, err = OpenReceiver("peer0", peerInterface.Index, "peer-link", family, peerInterface.Addresses)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := observer.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := observer.Socket.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := sender.Questions(context.Background(), "host.local.", []uint16{dns.TypeA, dns.TypeAAAA}); err != nil {
				t.Fatal(err)
			}
			question, err := observer.Receive()
			if err != nil || question.SourcePort != 5353 || question.DestinationPort != 5353 || question.HopLimit != 255 || question.Source.String() != address || question.Destination != multicast(family) {
				t.Fatal("fresh question metadata", question, err)
			}
			var decoded dns.Msg
			if err := decoded.Unpack(question.Wire); err != nil || decoded.Response || len(decoded.Question) != 2 || len(decoded.Answer) != 0 {
				t.Fatal("fresh question included client sections", err)
			}
			if err := sender.Goodbyes(context.Background(), []catalog.Answer{{RR: rr, Unique: true}}); err != nil {
				t.Fatal(err)
			}
			goodbye, err := observer.Receive()
			if err != nil {
				t.Fatal("full fragmented goodbye", err)
			}
			if err := decoded.Unpack(goodbye.Wire); err != nil || !decoded.Response || len(decoded.Answer) != 1 || decoded.Answer[0].Header().Ttl != 0 || decoded.Answer[0].Header().Class != dns.ClassINET|0x8000 {
				t.Fatal("invalid scoped goodbye", err)
			}
		})
	}
}

func TestLinkMonitorReportsIsolatedAddressChangeAndCloses(t *testing.T) {
	lan, _, iface, _ := networkLab(t)
	var monitor *LinkMonitor
	if err := lan.With(func() error { var err error; monitor, err = OpenMonitor(); return err }); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := monitor.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := lan.With(func() error {
		return exec.Command("ip", "address", "add", "198.51.100.1/32", "dev", "lo").Run()
	}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.socket.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Wait([]int{iface.Index}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("unrelated interface invalidated LAN topology", err)
	}
	if err := lan.With(func() error {
		command := exec.Command("ip", "address", "add", "192.0.2.2/24", "dev", "lan0")
		return command.Run()
	}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Wait([]int{iface.Index}); err != nil {
		t.Fatal("address notification missing", err)
	}
}
