// Package gateway supplies bounded catalog, lookup and publication HTTP adapters.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
)

const MaxRequestBytes = 16384

// Client targets one fixed numeric endpoint, with no proxy or redirect fallback.
type Client struct {
	url     string
	client  *http.Client
	refresh sync.Mutex
}

// NewClient creates a bounded HTTP/1.1 client for the configured endpoint.
func NewClient(endpoint config.Endpoint) (*Client, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: 5 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("gateway redirects are prohibited") }}
	return &Client{url: "http://" + net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), client: client}, nil
}

// Post performs one fixed operation with explicit length and JSON framing.
func (c *Client) Post(ctx context.Context, path string, data []byte, expected int) (_ []byte, err error) {
	if (path != "/v1/catalog" && path != "/v1/lookup" && path != "/v1/publications") || len(data) < 1 || len(data) > MaxRequestBytes {
		return nil, errors.New("invalid gateway operation")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != expected {
		return nil, fmt.Errorf("gateway HTTP status %d", response.StatusCode)
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.ContentLength < 1 || response.ContentLength > catalog.MaxFeedBytes || len(response.TransferEncoding) > 0 || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("invalid gateway response framing")
	}
	for _, values := range response.Header {
		if len(values) != 1 {
			return nil, errors.New("duplicate gateway response header")
		}
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, catalog.MaxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != response.ContentLength {
		return nil, errors.New("incomplete gateway response")
	}
	return data, nil
}

// Refresh correlates one catalog response with a fresh request challenge.
func (c *Client) Refresh(ctx context.Context, feed *catalog.NodeFeed) (int64, error) {
	c.refresh.Lock()
	defer c.refresh.Unlock()
	nonce, err := feed.BeginRequest()
	if err != nil {
		return 0, err
	}
	defer feed.AbortRequest()
	data, err := json.Marshal(struct {
		Schema int    `json:"schema"`
		Nonce  string `json:"nonce"`
	}{1, nonce})
	if err != nil {
		return 0, err
	}
	response, err := c.Post(ctx, "/v1/catalog", data, http.StatusOK)
	if err != nil {
		return 0, err
	}
	return feed.Accept(response, catalog.Now())
}
