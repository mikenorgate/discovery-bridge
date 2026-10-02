package linuxnet_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"golang.org/x/sys/unix"
)

func TestDescriptorHandoff(t *testing.T) {
	t.Parallel()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range pair {
		t.Cleanup(func() {
			if err := unix.Close(fd); err != nil {
				t.Error(err)
			}
		})
	}
	file, err := os.CreateTemp(t.TempDir(), "descriptor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := linuxnet.Send(pair[0], map[string]string{"op": "add", "uid": "pod-1"}, []int{int(file.Fd())}); err != nil {
		t.Fatal(err)
	}
	data, fds, err := linuxnet.Receive(pair[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d descriptors", len(fds))
	}
	t.Cleanup(func() {
		if err := unix.Close(fds[0]); err != nil {
			t.Error(err)
		}
	})
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received descriptor not CLOEXEC: %v", err)
	}
	var message map[string]string
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatal(err)
	}
	if message["uid"] != "pod-1" {
		t.Fatal("message changed")
	}
	if err := linuxnet.Send(pair[0], strings.Repeat("x", linuxnet.MaxMessage), nil); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestHostNamespaceRejected(t *testing.T) {
	t.Parallel()
	if ns, err := linuxnet.Open("/proc", os.Getpid()); err == nil {
		if err := ns.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("broker namespace admitted")
	}
	if _, err := linuxnet.Open("/proc", 1); err == nil {
		t.Fatal("host PID admitted")
	}
}
