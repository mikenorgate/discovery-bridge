package publication

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

type fixtureOwner struct {
	mu                sync.Mutex
	accepted, cleared int
	failure           error
	conflicts         []string
	failed            chan struct{}
	changed           chan struct{}
}

func (f *fixtureOwner) Reconcile(context.Context, []avahi.Intent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted++
	return f.failure
}
func (f *fixtureOwner) Clear(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared++
	select {
	case f.changed <- struct{}{}:
	default:
	}
	return f.failure
}
func (f *fixtureOwner) Failed() <-chan struct{} { return f.failed }
func (f *fixtureOwner) Conflicts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.conflicts...)
}
func (f *fixtureOwner) Err() error { f.mu.Lock(); defer f.mu.Unlock(); return f.failure }

func startServer(t *testing.T, uid uint32) (string, *fixtureOwner) {
	t.Helper()
	// Short temp paths also fit Linux's Unix socket limit in CI's build directories.
	dir, err := os.MkdirTemp("", "pub-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "publisher")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	owner := &fixtureOwner{failed: make(chan struct{}), changed: make(chan struct{}, 8)}
	server := Server{Owner: owner, Admission: admissionFixture(), ProducerUID: uid}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("publication server did not join")
		}
	})
	return path, owner
}

func TestUnixPeerUIDAndSingleProducerAdmission(t *testing.T) {
	path, owner := startServer(t, uint32(os.Geteuid()+1))
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := connection.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("unauthorized peer was retained")
	}
	_ = connection.Close()
	owner.mu.Lock()
	accepted, cleared := owner.accepted, owner.cleared
	owner.mu.Unlock()
	if accepted != 0 || cleared != 0 {
		t.Fatal("unauthorized producer changed publication")
	}
	path, owner = startServer(t, uint32(os.Geteuid()))
	client, err := Dial(context.Background(), path, "test-boot")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("competing producer was retained")
	}
	_ = second.Close()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.changed:
	case <-time.After(time.Second):
		t.Fatal("producer disconnect did not clear publication")
	}
	owner.mu.Lock()
	accepted, cleared = owner.accepted, owner.cleared
	owner.mu.Unlock()
	if accepted != 1 || cleared != 1 {
		t.Fatal(accepted, cleared)
	}
}

func TestInvalidReplacementClearsPreviouslyAdmittedProducer(t *testing.T) {
	path, owner := startServer(t, uint32(os.Geteuid()))
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload, err := Frame("test-boot", 1, catalog.Now().Mono, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if reply, err := reader.ReadString('\n'); err != nil || reply != "OK\n" {
		t.Fatal(reply, err)
	}
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	} // Exact replay.
	if _, err := reader.ReadString('\n'); err == nil {
		t.Fatal("replay did not close producer")
	}
	select {
	case <-owner.changed:
	case <-time.After(time.Second):
		t.Fatal("invalid frame did not clear publication")
	}
}

func TestOwnerFailureWakesIdleProducerAndPreservesConflictResponse(t *testing.T) {
	path, owner := startServer(t, uint32(os.Geteuid()))
	client, err := Dial(context.Background(), path, "test-boot")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Send(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	owner.failure = errors.New("conflict")
	owner.conflicts = []string{"host-alias.local."}
	owner.mu.Unlock()
	close(owner.failed)
	// Force the next write to fail while leaving the final response readable.
	// The publisher can close between snapshots, before the producer next sends.
	if err := client.connection.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var conflict *Conflict
	if err := client.Send(context.Background(), nil); !errors.As(err, &conflict) || len(conflict.Names) != 1 || conflict.Names[0] != "host-alias.local." {
		t.Fatal("owner loss lost conflict reply", err)
	}
}
