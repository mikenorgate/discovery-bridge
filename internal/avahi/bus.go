// Package avahi uses Avahi's local D-Bus API for scoped browsing and publication.
package avahi

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	service          = "org.freedesktop.Avahi"
	server           = service + ".Server"
	server2          = service + ".Server2"
	browserInterface = service + ".RecordBrowser"
	busInterface     = "org.freedesktop.DBus"
	callTimeout      = 3 * time.Second
)

var uniqueOwner = regexp.MustCompile(`^:[0-9]+\.[0-9]+$`)

var errInitializing = errors.New("avahi is initializing")

// bus is one connection epoch. Overflow or daemon loss invalidates all its work.
// The library's default signal handler buffers overflow in extra goroutines;
// this handler has one fixed queue and closes the connection on overflow.
type bus struct {
	mu      sync.Mutex
	owner   string
	failure error
	failed  chan struct{}
	signals chan *dbus.Signal
	socket  *net.UnixConn
	conn    *dbus.Conn
	done    chan struct{}
}

func newBus() *bus {
	return &bus{failed: make(chan struct{}), signals: make(chan *dbus.Signal, 512), done: make(chan struct{})}
}

func (b *bus) fail(err error) {
	b.mu.Lock()
	first := b.failure == nil
	if b.failure == nil {
		b.failure = err
		close(b.failed)
	}
	socket := b.socket
	b.mu.Unlock()
	if first && socket != nil {
		// Close the transport directly. Conn.Close first waits for godbus' writer
		// lock; a stalled local daemon must not hold that lock past a source lease.
		_ = socket.Close()
	}
}

func (b *bus) err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failure
}

func (b *bus) Terminate() { b.fail(errors.New("avahi D-Bus connection closed")) }

func (b *bus) DeliverSignal(_ string, _ string, signal *dbus.Signal) {
	b.mu.Lock()
	owner, failure := b.owner, b.failure
	b.mu.Unlock()
	if failure != nil || signal == nil {
		return
	}
	if signal.Sender == busInterface && signal.Name == busInterface+".NameOwnerChanged" {
		var name, previous, current string
		if err := dbus.Store(signal.Body, &name, &previous, &current); err != nil {
			b.fail(errors.New("invalid Avahi ownership event"))
		} else if name == service && owner != "" && current != owner {
			b.fail(errors.New("avahi owner changed; discard observation epoch"))
		}
		return
	}
	if owner == "" || signal.Sender != owner {
		return
	}
	if signal.Path == "/" && signal.Name == server+".StateChanged" {
		var state int32
		var detail string
		if err := dbus.Store(signal.Body, &state, &detail); err != nil || state != 2 {
			if err == nil && (state == 0 || state == 1) {
				b.fail(errInitializing)
			} else {
				b.fail(errors.New("avahi left running state"))
			}
		}
		return
	}
	select {
	case b.signals <- signal:
	default:
		b.fail(errors.New("avahi signal queue overflow; discard observation epoch"))
	}
}

func connectBus(ctx context.Context, path string) (*bus, error) {
	// Avahi's systemd unit becomes active before address probing reaches RUNNING.
	// Retry only initialization, with no observations or registrations admitted.
	// Each failed attempt closes its epoch; an established epoch still fails
	// immediately on state or owner loss.
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		b, err := connectBusOnce(ctx, startup, path)
		if !errors.Is(err, errInitializing) {
			return b, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return nil, errors.Join(err, startup.Err())
		case <-timer.C:
		}
	}
}

func connectBusOnce(ctx, startupContext context.Context, path string) (*bus, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
		return nil, errors.New("absolute local Unix D-Bus socket path required")
	}
	startup, cancel := context.WithTimeout(startupContext, callTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(startup, "unix", path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if raw != nil {
			_ = raw.Close()
		}
	}()
	uconn, ok := raw.(*net.UnixConn)
	if !ok {
		return nil, errors.New("D-Bus transport is not a local Unix socket")
	}
	deadline, _ := startup.Deadline()
	if err := uconn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	b := newBus()
	b.socket = uconn
	b.conn, err = dbus.DialUnix(uconn, dbus.WithContext(ctx), dbus.WithSignalHandler(b))
	if err != nil {
		return nil, err
	}
	raw = nil // The private D-Bus connection now owns the socket.
	go func() {
		defer close(b.done)
		select {
		case <-b.failed:
		case <-b.conn.Context().Done():
			b.fail(errors.New("avahi D-Bus disconnected"))
		}
		_ = b.conn.Close()
	}()
	stop := context.AfterFunc(startup, func() { b.fail(errors.New("avahi D-Bus startup interrupted")) })
	defer stop()
	if err = b.conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(unix.Geteuid()))}); err == nil {
		err = b.conn.Hello()
	}
	if err == nil {
		err = uconn.SetDeadline(time.Time{})
	}
	if err == nil {
		err = b.conn.BusObject().CallWithContext(startup, busInterface+".AddMatch", 0,
			"type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.Avahi'").Err
	}
	var owner, current string
	if err == nil {
		err = b.conn.BusObject().CallWithContext(startup, busInterface+".GetNameOwner", 0, service).Store(&owner)
	}
	if err == nil && !uniqueOwner.MatchString(owner) {
		err = errors.New("invalid Avahi unique owner")
	}
	if err == nil {
		b.mu.Lock()
		b.owner = owner
		b.mu.Unlock()
		err = b.conn.BusObject().CallWithContext(startup, busInterface+".AddMatch", 0, "type='signal',sender='"+owner+"'").Err
	}
	if err == nil {
		err = b.conn.BusObject().CallWithContext(startup, busInterface+".GetNameOwner", 0, service).Store(&current)
	}
	var state int32
	if err == nil {
		err = b.call(startup, "/", server+".GetState").Store(&state)
	}
	if err == nil && (owner != current || state != 2) {
		if owner == current && (state == 0 || state == 1) {
			err = errInitializing
		} else {
			err = errors.New("avahi is not stable and running")
		}
	}
	if err == nil {
		err = b.err()
	}
	if err != nil {
		b.fail(err)
		b.close()
		return nil, err
	}
	return b, nil
}

func (b *bus) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) *dbus.Call {
	if err := b.err(); err != nil {
		return &dbus.Call{Err: err}
	}
	bounded, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	b.mu.Lock()
	owner := b.owner
	b.mu.Unlock()
	result := b.conn.Object(owner, path).CallWithContext(bounded, method, 0, args...)
	if result.Err == nil {
		result.Err = b.err()
	}
	return result
}

func (b *bus) close() {
	b.fail(errors.New("avahi connection closed"))
	if b.conn != nil {
		_ = b.conn.Close()
		<-b.done
	}
}
