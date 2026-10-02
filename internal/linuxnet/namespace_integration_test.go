//go:build integration && linux

package linuxnet_test

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"golang.org/x/sys/unix"
)

func TestNamespaceSocketsAndRestoration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("namespace integration must run with root privileges")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "unshare", "--net", "sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := child.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	})
	var ns *linuxnet.Namespace
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
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
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "dummy0", "type", "dummy"}, {"link", "set", "dummy0", "up", "multicast", "on"}, {"address", "add", "192.0.2.42/24", "dev", "dummy0"}, {"address", "add", "2001:db8:1::42/64", "dev", "dummy0", "nodad"}} {
		command := exec.CommandContext(ctx, "nsenter", "--target", strconv.Itoa(child.Process.Pid), "--net", "ip")
		command.Args = append(command.Args, args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("namespace setup: %v: %s", err, output)
		}
	}
	details, err := ns.Inspect("dummy0", []netip.Addr{netip.MustParseAddr("192.0.2.42"), netip.MustParseAddr("2001:db8:1::42")})
	if err != nil || details.Index < 1 {
		t.Fatal("namespace interface inspection failed", details, err)
	}
	if _, err := ns.Inspect("dummy0", []netip.Addr{netip.MustParseAddr("2001:db8:1::43")}); err == nil {
		t.Fatal("accepted API/interface address mismatch")
	}
	before, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{4, 6} {
		socket, err := ns.Socket("dummy0", family)
		if err != nil {
			t.Fatal(err)
		}
		address, err := unix.Getsockname(int(socket.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		switch value := address.(type) {
		case *unix.SockaddrInet4:
			if family != 4 || value.Port != 5353 {
				t.Fatal("incorrect v4 socket")
			}
		case *unix.SockaddrInet6:
			if family != 6 || value.Port != 5353 {
				t.Fatal("incorrect v6 socket")
			}
		default:
			t.Fatal("unexpected socket family")
		}
		if err := socket.Close(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat("/proc/self/ns/net")
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("broker namespace not restored")
	}
	path := filepath.Join("/proc", strconv.Itoa(child.Process.Pid), "ns/net")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("sandbox unexpectedly exited")
	}
}
