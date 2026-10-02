//go:build integration

package avahi

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDeadlineClosesTransportEvenWhenDBusWriterStalls(t *testing.T) {
	path, daemon := privateBusProcess(t)
	avahiFixture(t, path, nil)
	b, err := connectBus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	raw, err := b.socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 1024) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if err := unix.Kill(daemon.Process.Pid, unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Kill(daemon.Process.Pid, unix.SIGCONT) }()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { b.fail(errors.New("publication lease expired")) })
	defer stop()
	done := make(chan error, 1)
	go func() { done <- b.call(ctx, "/", server+".Stalled", make([]byte, 64*1024)).Err }()
	select {
	case err := <-done:
		if err == nil || b.err() == nil {
			t.Fatal("stalled writer did not lose its ownership epoch", err)
		}
	case <-time.After(time.Second):
		t.Fatal("D-Bus writer lock prevented transport withdrawal at deadline")
	}
}
