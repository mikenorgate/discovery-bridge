package discoverydns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

func (h *Handler) admitted(address net.Addr) bool {
	if address == nil {
		return false
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return false
	}
	ip := endpoint.Addr().Unmap()
	for _, prefix := range h.clients {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *Handler) response(ctx context.Context, remote net.Addr, network string, request *dns.Msg) *dns.Msg {
	var reply *dns.Msg
	if !h.admitted(remote) {
		reply = new(dns.Msg)
		reply.SetRcode(request, dns.RcodeRefused)
	} else {
		reply = h.Answer(ctx, request)
	}
	limit := 65535
	if network == "udp" {
		limit = 512
		if opt := request.IsEdns0(); opt != nil {
			limit = max(512, min(int(opt.UDPSize()), 1232))
			if reply.IsEdns0() == nil {
				reply.SetEdns0(uint16(limit), false)
			}
		}
	}
	reply.Compress = true
	reply.Truncate(limit)
	return reply
}

func (h *Handler) serve(ctx context.Context, writer dns.ResponseWriter, request *dns.Msg) {
	reply := h.response(ctx, writer.RemoteAddr(), writer.LocalAddr().Network(), request)
	// A disconnected DNS client has no persistent state to roll back.
	_ = writer.WriteMsg(reply)
}

// Serve owns listeners for both DNS transports and joins all servers on exit.
func (h *Handler) Serve(ctx context.Context) error {
	servers := make([]*dns.Server, 0, len(h.settings.Listeners)*2)
	tcpListeners := make([]net.Listener, 0, len(h.settings.Listeners))
	tcpConnections := make(chan struct{}, maxTCPConnections)
	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	failures := make(chan error, len(h.settings.Listeners)*2)
	defer func() {
		cancel()
		for _, server := range servers {
			_ = server.Shutdown()
			if server.Listener != nil {
				_ = server.Listener.Close()
			}
			if server.PacketConn != nil {
				_ = server.PacketConn.Close()
			}
		}
		for _, listener := range tcpListeners {
			_ = listener.Close() // Closing listeners releases the owned accept loops.
		}
		workers.Wait()
	}()
	for _, endpoint := range h.settings.Listeners {
		address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
		family := "4"
		if netip.MustParseAddr(endpoint.Host).Is6() {
			family = "6"
		}
		for _, transport := range []string{"udp", "tcp"} {
			server := &dns.Server{
				Net: transport + family, Addr: address, UDPSize: 1232,
				ReadTimeout: 2 * time.Second, WriteTimeout: 8 * time.Second,
				IdleTimeout:   func() time.Duration { return 8 * time.Second },
				MaxTCPQueries: 64,
				Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
					h.serve(stop, writer, request)
				}),
			}
			if transport == "udp" {
				packet, err := (&net.ListenConfig{}).ListenPacket(stop, server.Net, address)
				if err != nil {
					return err
				}
				server.PacketConn = packet
			} else {
				listener, err := (&net.ListenConfig{}).Listen(stop, server.Net, address)
				if err != nil {
					return err
				}
				tcpListeners = append(tcpListeners, listener)
				workers.Go(func() { failures <- h.serveTCP(stop, listener, tcpConnections) })
				continue
			}
			servers = append(servers, server)
			workers.Go(func() { failures <- server.ActivateAndServe() })
		}
	}
	select {
	case <-stop.Done():
		return stop.Err()
	case err := <-failures:
		return err
	}
}

// Run authenticates the collector account once and runs the authoritative service.
func Run(ctx context.Context, settings Config) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	account, err := user.Lookup(settings.CollectorUser)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || uid == uint64(^uint32(0)) {
		return errors.New("discovery dns: unprivileged collector account required")
	}
	handler, err := New(settings, &native.Client{Socket: settings.NativeSocket, ServerUID: uint32(uid)})
	if err != nil {
		return err
	}
	return handler.Serve(ctx)
}
