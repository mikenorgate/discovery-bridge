package discoverydns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxTCPConnections = 64
	maxTCPInFlight    = 16
	maxTCPRequests    = 64
)

// serveTCP bounds connections across all listeners. The DNS library's default
// TCP handler processes a connection serially, delaying cached answers behind
// cold multicast lookups. Keep its message codec, but own request scheduling.
func (h *Handler) serveTCP(ctx context.Context, listener net.Listener, slots chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var connections sync.WaitGroup
	defer func() {
		cancel()
		connections.Wait()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			connections.Go(func() {
				defer func() { <-slots }()
				h.serveTCPConn(ctx, conn)
			})
		default:
			_ = conn.Close() // Reject excess connections without allocating workers.
		}
	}
}

func (h *Handler) serveTCPConn(ctx context.Context, conn net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		_ = conn.Close() // Cancellation must interrupt both socket directions.
		close(closed)
	})
	stream := &dns.Conn{Conn: conn}
	replies := make(chan *dns.Msg)
	written := make(chan struct{})
	go func() {
		defer close(written)
		for reply := range replies {
			if ctx.Err() != nil {
				return
			}
			if err := stream.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
				cancel()
				return
			}
			if err := stream.WriteMsg(reply); err != nil {
				cancel()
				return
			}
		}
	}()
	var requests sync.WaitGroup
	drain := false
	defer func() {
		if !drain {
			cancel()
		}
		requests.Wait()
		close(replies)
		<-written
		cancel()
		<-closed
	}()
	slots := make(chan struct{}, maxTCPInFlight)
	timeout := 2 * time.Second
	for range maxTCPRequests {
		if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
		request, err := stream.ReadMsg()
		if err != nil {
			return
		}
		timeout = 8 * time.Second
		select {
		case slots <- struct{}{}:
			requests.Go(func() {
				defer func() { <-slots }()
				reply := h.response(ctx, conn.RemoteAddr(), "tcp", request)
				select {
				case replies <- reply:
				case <-ctx.Done():
				}
			})
		default:
			// Do not queue excess requests or let one connection own all work.
			reply := new(dns.Msg)
			reply.SetRcode(request, dns.RcodeServerFailure)
			select {
			case replies <- reply:
			case <-ctx.Done():
				return
			}
		}
	}
	// At the request limit, finish all admitted replies before closing. EOF,
	// shutdown and write failure instead cancel the connection's pending work.
	drain = true
}
