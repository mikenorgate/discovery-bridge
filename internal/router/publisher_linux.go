package router

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/publication"
	"github.com/mikenorgate/discovery-bridge/internal/state"
	"golang.org/x/sys/unix"
)

func bootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if len(value) != 36 || strings.ContainsAny(value, "\x00\n ") {
		return "", errors.New("invalid Linux boot identity")
	}
	return value, nil
}

// localListener retains an exclusive process lock while replacing a stale socket.
// A competing publisher cannot unlink the active publisher's IPC endpoint.
func localListener(path string) (_ *net.UnixListener, _ *os.File, err error) {
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, err
	}
	lock := os.NewFile(uintptr(fd), "local publisher lock")
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Geteuid()) {
			return nil, nil, errors.New("publisher path is not an owned stale socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0660); err != nil {
		return nil, nil, errors.Join(err, listener.Close())
	}
	return listener, lock, nil
}

// RunPublisher owns Avahi advertisements independently of the collector process.
// Its only accepted producer is the configured local Unix account.
func RunPublisher(ctx context.Context, settings config.Router) (err error) {
	if err := settings.Validate(); err != nil {
		return err
	}
	account, err := user.Lookup(settings.ProducerUser)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || uid == uint64(^uint32(0)) {
		return errors.New("unprivileged local producer account required")
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	identities, err := state.Open(ctx, settings.State, settings.AliasPrefix)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, identities.Close()) }()
	monitor, err := observation.OpenMonitor()
	if err != nil {
		return err
	}
	defer func() { _ = monitor.Close() }()
	t, err := capture(settings, false)
	if err != nil {
		return err
	}
	defer func() { _ = t.close() }()
	stop, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = monitor.Wait()
		// Close the old transmitters before relinquishing publication ownership:
		// an interface index may now refer to a different link.
		_ = t.close()
		cancel(errors.New("publisher link or address generation changed"))
	}()
	defer func() { _ = monitor.Close(); <-finished }()
	owner, err := avahi.ConnectPublisher(stop, settings.BusSocket, t.links, func(ctx context.Context, index, family int, answers []catalog.Answer) error {
		sender := t.senders[socketKey{index, family}]
		if sender == nil {
			return errors.New("missing captured goodbye sender")
		}
		return sender.Goodbyes(ctx, answers)
	})
	if err != nil {
		return err
	}
	var lock *os.File
	defer func() {
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		err = errors.Join(err, owner.Close(bounded))
		if lock != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	listener, acquired, err := localListener(settings.PublisherSocket)
	if err != nil {
		return err
	}
	lock = acquired
	defer func() { _ = listener.Close() }()
	additional := make(map[string]bool)
	if settings.Publication != nil {
		additional[settings.Publication.Source] = true
	}
	server := publication.Server{Owner: owner, ProducerUID: uint32(uid), Admission: publication.Admission{
		Boot: boot, Links: t.links, Sources: additional,
		Owns:     func(name string) (bool, error) { return identities.Owns(stop, name) },
		OwnsHost: func(source, name string) (bool, error) { return identities.OwnsHost(stop, source, name) },
	}, Watchdog: func() {
		if err := notify(stop, true); err != nil {
			cancel(err)
		}
	}}
	err = server.Serve(stop, listener)
	if stop.Err() != nil {
		return context.Cause(stop)
	}
	return err
}
