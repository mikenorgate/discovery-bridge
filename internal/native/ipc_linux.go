package native

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"golang.org/x/sys/unix"
)

const maxFrame = 131072

// Querier is the read-only interface shared by the collector and DNS frontend.
type Querier interface {
	Query(context.Context, Question) (Result, error)
}

type request struct {
	Schema   int    `json:"schema"`
	Source   string `json:"source"`
	Question []byte `json:"question"`
}

type response struct {
	Schema int    `json:"schema"`
	Status string `json:"status"`
	Epoch  string `json:"epoch"`
	Wire   []byte `json:"wire"`
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
	if err := errors.Join(err, credentialErr); err != nil {
		return 0, err
	}
	if credentials == nil {
		return 0, errors.New("native: missing unix peer credentials")
	}
	return credentials.Uid, nil
}

// Serve admits only the configured frontend UID and at most 64 active requests.
// It owns the listener and joins all handlers before returning.
func Serve(ctx context.Context, listener *net.UnixListener, uid uint32, backend Querier) error {
	if listener == nil || backend == nil || uid == 0 || uid == ^uint32(0) {
		return errors.New("native: listener, backend and unprivileged client required")
	}
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	slots := make(chan struct{}, 64)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		peer, err := peerUID(connection)
		if err != nil || peer != uid {
			_ = connection.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() {
				defer func() { <-slots }()
				serveOne(ctx, connection, backend)
			})
		default:
			_ = connection.Close()
		}
	}
}

func serveOne(ctx context.Context, connection *net.UnixConn, backend Querier) {
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	data, err := jsonwire.ReadLine(bufio.NewReader(connection), 4096)
	if err != nil {
		return
	}
	var input request
	if jsonwire.Decode(data, 4096, &input) != nil || input.Schema != 1 || len(input.Source) > 128 {
		return
	}
	message, err := dnswire.Decode(input.Question, 1232, 1, 0)
	if err != nil || message.Response || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	result, err := backend.Query(bounded, Question{Source: input.Source, DNS: message.Question[0]})
	output := response{Schema: 1, Status: "unavailable", Wire: []byte{}}
	if errors.Is(err, ErrBusy) {
		output.Status = "busy"
	}
	if err == nil {
		reply := new(dns.Msg)
		reply.SetReply(message)
		reply.Authoritative = true
		reply.Answer = result.Records
		wire, packErr := reply.Pack()
		if packErr == nil && len(wire) <= 65535 {
			output.Status, output.Epoch, output.Wire = "ok", result.Epoch, wire
		}
	}
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	// A failed response write has no persistent effect; closing revokes the request.
	_ = json.NewEncoder(connection).Encode(output)
}

// Client authenticates the collector endpoint and performs one bounded query.
type Client struct {
	Socket    string
	ServerUID uint32
}

// Query preserves the caller's deadline and carries native records, not strings.
func (c *Client) Query(ctx context.Context, question Question) (Result, error) {
	if c.Socket == "" || c.ServerUID == 0 || c.ServerUID == ^uint32(0) {
		return Result{}, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", c.Socket)
	if err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	defer func() { _ = connection.Close() }()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Result{}, ErrUnavailable
	}
	uid, err := peerUID(unixConnection)
	if err != nil || uid != c.ServerUID {
		return Result{}, ErrUnavailable
	}
	stop := context.AfterFunc(bounded, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return Result{}, err
	}
	message := &dns.Msg{Question: []dns.Question{question.DNS}}
	wire, err := message.Pack()
	if err != nil {
		return Result{}, err
	}
	if err := json.NewEncoder(connection).Encode(request{Schema: 1, Source: question.Source, Question: wire}); err != nil {
		return Result{}, err
	}
	data, err := jsonwire.ReadLine(bufio.NewReader(connection), maxFrame)
	if err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	var output response
	if err := jsonwire.Decode(data, maxFrame, &output); err != nil || output.Schema != 1 {
		return Result{}, ErrUnavailable
	}
	if output.Status == "busy" {
		return Result{}, ErrBusy
	}
	if output.Status != "ok" || output.Epoch == "" || len(output.Epoch) > 128 {
		return Result{}, ErrUnavailable
	}
	reply, err := dnswire.Decode(output.Wire, 65535, 1, 256)
	if err != nil || !reply.Response || !reply.Authoritative || reply.Rcode != dns.RcodeSuccess || len(reply.Question) != 1 {
		return Result{}, ErrUnavailable
	}
	q := reply.Question[0]
	if catalog.NameKey(q.Name) != catalog.NameKey(question.DNS.Name) || q.Qtype != question.DNS.Qtype || q.Qclass != question.DNS.Qclass {
		return Result{}, ErrUnavailable
	}
	return Result{Epoch: output.Epoch, Records: reply.Answer}, nil
}
