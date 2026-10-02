package publication

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"golang.org/x/sys/unix"
)

// Owner is the independent Avahi publication owner used by the local IPC server.
type Owner interface {
	Reconcile(context.Context, []avahi.Intent) error
	Clear(context.Context) error
	Failed() <-chan struct{}
	Conflicts() []string
	Err() error
}

// Server admits one producer at a time by kernel Unix peer credentials.
type Server struct {
	Owner       Owner
	Admission   Admission
	ProducerUID uint32
	Watchdog    func()
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err = errors.Join(err, credentialErr); err != nil {
		return 0, err
	}
	return credentials.Uid, nil
}

// Serve takes ownership of the already configured Unix listener. Unauthorized or
// competing clients never change publication. Producer loss clears all its groups.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if s.Owner == nil || s.Admission.Boot == "" || s.Admission.Owns == nil || len(s.Admission.Links) == 0 {
		return errors.New("publication server requires an owner and explicit admission")
	}
	defer func() { _ = listener.Close() }()
	var mu sync.Mutex
	var producer *net.UnixConn
	var workers sync.WaitGroup
	finished := make(chan struct{})
	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer close(finished)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop.Done():
			case <-s.Owner.Failed():
			case <-ticker.C:
				if s.Watchdog != nil && s.Owner.Err() == nil {
					s.Watchdog()
				}
				continue
			}
			_ = listener.Close()
			mu.Lock()
			if producer != nil {
				// Wake the producer handler while preserving its final CONFLICT reply.
				_ = producer.CloseRead()
			}
			mu.Unlock()
			return
		}
	}()
	defer func() { cancel(); <-finished; workers.Wait() }()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if failure := s.Owner.Err(); failure != nil {
				return failure
			}
			return err
		}
		uid, err := peerUID(connection)
		mu.Lock()
		if err != nil || uid != s.ProducerUID || producer != nil || s.Owner.Err() != nil {
			mu.Unlock()
			_ = connection.Close()
			continue
		}
		producer = connection
		mu.Unlock()
		workers.Go(func() {
			s.client(stop, connection)
			mu.Lock()
			producer = nil
			mu.Unlock()
		})
	}
}

func frameLine(reader *bufio.Reader) ([]byte, error) {
	var result []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(result)+len(part) > MaxFrame {
			return nil, errors.New("local publication frame byte limit")
		}
		result = append(result, part...)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func (s *Server) client(ctx context.Context, connection *net.UnixConn) {
	defer func() { _ = connection.Close() }()
	defer func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Owner.Clear(bounded) // A failed owner has already lost its D-Bus connection.
		if names := s.Owner.Conflicts(); len(names) > 0 {
			payload, err := json.Marshal(names)
			if err == nil && len(payload)+10 <= MaxFrame {
				_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = connection.Write(append(append([]byte("CONFLICT "), payload...), '\n'))
			}
		}
	}()
	reader := bufio.NewReaderSize(connection, 64*1024)
	var previous int64
	for {
		if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		payload, err := frameLine(reader)
		if err != nil {
			return
		}
		sequence, groups, err := s.Admission.Decode(payload, catalog.Now().Mono, previous)
		if err != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = s.Owner.Reconcile(bounded, groups)
		cancel()
		if err != nil {
			return
		}
		previous = sequence
		if err := connection.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return
		}
		if n, err := connection.Write([]byte("OK\n")); err != nil || n != 3 {
			return
		}
	}
}
