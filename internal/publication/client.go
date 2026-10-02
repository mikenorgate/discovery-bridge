package publication

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
)

// Conflict reports unique names that the collector must resolve before retrying.
type Conflict struct{ Names []string }

func (c *Conflict) Error() string { return "Avahi publication conflict" }

// Client owns one local publication producer session and strictly increasing sequence.
type Client struct {
	mu         sync.Mutex
	connection net.Conn
	reader     *bufio.Reader
	boot       string
	sequence   int64
}

// Dial opens only an explicit absolute Unix socket; no TCP transport is accepted.
func Dial(ctx context.Context, path, boot string) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 || boot == "" {
		return nil, errors.New("local publisher path and boot identity required")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{connection: connection, reader: bufio.NewReaderSize(connection, 64*1024), boot: boot}, nil
}

// Send transfers a complete snapshot and waits at most three seconds for admission.
func (c *Client) Send(ctx context.Context, intents []avahi.Intent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.sequence >= math.MaxInt64-1 {
		return errors.New("publication sequence exhausted")
	}
	deadline := time.Now().Add(3 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := c.connection.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.connection.Close() })
	defer stop()
	c.sequence++
	payload, err := Frame(c.boot, c.sequence, catalog.Now().Mono, intents)
	if err != nil {
		return err
	}
	if n, err := c.connection.Write(payload); err != nil || n != len(payload) {
		return errors.New("local publication transfer failed")
	}
	reply, err := frameLine(c.reader)
	if err != nil {
		return err
	}
	if string(reply) == "OK\n" {
		return nil
	}
	if strings.HasPrefix(string(reply), "CONFLICT ") {
		var names []string
		if err := jsonwire.Decode(reply[len("CONFLICT "):], MaxFrame, &names); err != nil || len(names) == 0 || len(names) > catalog.MaxRecords {
			return errors.New("invalid publication conflict response")
		}
		for _, name := range names {
			if !catalog.LocalName(name) {
				return errors.New("foreign publication conflict name")
			}
		}
		return &Conflict{Names: names}
	}
	return errors.New("local publisher rejected snapshot")
}

// Close releases the producer; the independent owner withdraws its publications.
func (c *Client) Close() error { return c.connection.Close() }
