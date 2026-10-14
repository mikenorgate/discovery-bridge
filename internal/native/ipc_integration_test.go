//go:build integration && linux

package native

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

type backendFunc func(context.Context, Question) (Result, error)

func (f backendFunc) Query(ctx context.Context, question Question) (Result, error) {
	return f(ctx, question)
}

func TestUnixQueryCredentialsAndWireRecords(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run the read-only IPC fixture as an unprivileged test user")
	}
	path := filepath.Join(t.TempDir(), "native.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Serve(ctx, listener, uint32(os.Geteuid()), backendFunc(func(_ context.Context, question Question) (Result, error) {
			if question.Source != "alpha" || question.DNS.Name != "device.local." {
				return Result{}, ErrUnavailable
			}
			return Result{Epoch: "generation", Records: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "device.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
				A:   net.ParseIP("192.0.2.10").To4(),
			}}}, nil
		}))
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	question := Question{Source: "alpha", DNS: dns.Question{Name: "device.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	client := &Client{Socket: path, ServerUID: uint32(os.Geteuid())}
	result, err := client.Query(t.Context(), question)
	if err != nil || result.Epoch != "generation" || len(result.Records) != 1 {
		t.Fatalf("IPC result=%+v err=%v", result, err)
	}
	client.ServerUID++
	if _, err := client.Query(t.Context(), question); !errors.Is(err, ErrUnavailable) {
		t.Fatal("impostor collector UID was accepted")
	}
}
