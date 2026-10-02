package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
)

// Handler serves one admitted operation; publication uses a separate listener.
type Handler func(context.Context, string, string, []byte) (int, []byte)

// Serve admits configured source prefixes before bounded HTTP parsing.
// The caller transfers listener ownership. Each connection carries one request.
func Serve(ctx context.Context, listener net.Listener, clients []netip.Prefix, handler Handler) error {
	if len(clients) < 1 || len(clients) > 32 || handler == nil {
		return errors.New("explicit bounded client prefixes and handler required")
	}
	for _, prefix := range clients {
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
			return errors.New("invalid gateway client prefix")
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() { _ = listener.Close() }()
	active := make(chan struct{}, 32)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
		address, parseErr := netip.ParseAddr(host)
		approved := false
		if err == nil && parseErr == nil {
			address = address.Unmap()
			for _, prefix := range clients {
				approved = approved || prefix.Contains(address)
			}
		}
		if !approved {
			_ = connection.Close()
			continue
		}
		select {
		case active <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-active; _ = connection.Close() }()
			deadline := time.Now().Add(5 * time.Second)
			if err := connection.SetDeadline(deadline); err != nil {
				return
			}
			requestCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			request, data, err := receiveRequest(connection)
			if err != nil {
				writeResponse(connection, 400, []byte(`{"error":"request"}`))
				return
			}
			status, result := handler(requestCtx, request.Method, request.RequestURI, data)
			writeResponse(connection, status, result)
		}()
	}
}

func receiveRequest(connection net.Conn) (*http.Request, []byte, error) {
	reader := bufio.NewReaderSize(connection, 8192)
	var header []byte
	seen := make(map[string]bool)
	for index := 0; ; index++ {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, nil, err
		}
		header = append(header, line...)
		if len(header) > 8192 || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, nil, errors.New("invalid or excessive HTTP header")
		}
		if index == 0 {
			parts := strings.Split(string(line[:len(line)-2]), " ")
			if len(parts) != 3 || parts[2] != "HTTP/1.1" {
				return nil, nil, errors.New("HTTP/1.1 required")
			}
			continue
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		key, _, ok := strings.Cut(string(line), ":")
		key = strings.ToLower(key)
		if !ok || seen[key] || key == "transfer-encoding" || key == "content-encoding" || key == "expect" || strings.TrimSpace(key) != key {
			return nil, nil, errors.New("duplicate or unsupported HTTP framing")
		}
		seen[key] = true
	}
	combined := bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader))
	request, err := http.ReadRequest(combined)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = request.Body.Close() }()
	if !seen["content-length"] || request.ContentLength < 1 || request.ContentLength > MaxRequestBytes || request.Header.Get("Content-Type") != "application/json" || len(request.TransferEncoding) > 0 {
		return nil, nil, errors.New("HTTP body size or type rejected")
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
	if err != nil || int64(len(data)) != request.ContentLength || combined.Buffered() > 0 || reader.Buffered() > 0 {
		return nil, nil, errors.New("incomplete or pipelined HTTP request")
	}
	return request, data, nil
}

func writeResponse(connection net.Conn, status int, data []byte) {
	if status < 200 || status > 599 || len(data) < 1 || len(data) > catalog.MaxFeedBytes {
		return
	}
	response := http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data)), Close: true}
	_ = response.Write(connection) // Peer disconnect does not change producer leases.
}

// CatalogAPI exposes read and lookup operations without publication authority.
func CatalogAPI(feed *Feed, lookups *Lookups) Handler {
	bucket := NewBucket(64, 128)
	return func(ctx context.Context, method, target string, data []byte) (int, []byte) {
		failure := func(status int) (int, []byte) { return status, []byte(`{"error":"request"}`) }
		if !bucket.Take(catalog.Now().Mono, 1) {
			return failure(429)
		}
		if method != http.MethodPost {
			return failure(405)
		}
		switch target {
		case "/v1/catalog":
			if feed == nil {
				return failure(503)
			}
			var request struct {
				Schema int    `json:"schema"`
				Nonce  string `json:"nonce"`
			}
			if err := jsonwire.Decode(data, MaxRequestBytes, &request); err != nil || request.Schema != 1 || !catalog.ValidNonce(request.Nonce) {
				return failure(400)
			}
			payload, err := feed.Read(request.Nonce, catalog.Now())
			if err != nil {
				return failure(503)
			}
			return 200, payload
		case "/v1/lookup":
			if lookups == nil {
				return failure(503)
			}
			count, err := lookups.Submit(ctx, data)
			if errors.Is(err, ErrBusy) {
				return failure(429)
			}
			if err != nil {
				if _, decodeErr := DecodeLookup(data); decodeErr != nil {
					return failure(400)
				}
				return failure(503)
			}
			payload, err := json.Marshal(struct {
				Schema   int `json:"schema"`
				Accepted int `json:"accepted"`
			}{1, count})
			if err != nil {
				return failure(503)
			}
			return 202, payload
		default:
			return failure(404)
		}
	}
}
