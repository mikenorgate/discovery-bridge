package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

// Receiver owns one admitted producer's replay watermark and absolute lease.
// Concurrent HTTP requests cannot replace state out of order or renew a replay.
type Receiver struct {
	mu        sync.Mutex
	source    string
	scopes    *policy.SourcePolicy
	issued    time.Time
	signature [32]byte
	observed  catalog.Moment
	deadline  time.Duration
	current   []catalog.Record
}

// NewReceiver binds the receiver to an immutable policy's explicit VIP source.
func NewReceiver(source string, scopes *policy.SourcePolicy) (*Receiver, error) {
	if source == "" || scopes == nil || len(scopes.Sources()[source]) == 0 || len(scopes.Sources()[source]) > 32 {
		return nil, errors.New("explicit bounded publication source required")
	}
	return &Receiver{source: source, scopes: scopes}, nil
}

// Install validates a full replacement before mutating its records or deadline.
func (r *Receiver) Install(data []byte, now catalog.Moment) error {
	var value Snapshot
	if err := jsonwire.Decode(data, gateway.MaxRequestBytes, &value); err != nil {
		return err
	}
	if value.Schema != 1 || value.Issued.IsZero() || value.Until.IsZero() || !value.Until.After(value.Issued) || value.Until.Sub(value.Issued) > Lease || value.Issued.Sub(now.Wall) > 2*time.Second || !value.Until.After(now.Wall) || now.Mono < 0 {
		return errors.New("invalid Service publication lease")
	}
	records, err := Records(value.Services, value.Until, r.source, r.scopes)
	if err != nil {
		return err
	}
	// Retain raw timestamp strings in canonical JSON: a changed payload at the
	// same issued_at cannot silently become an accepted renewal.
	var canonical map[string]any
	if err := jsonwire.Decode(data, gateway.MaxRequestBytes, &canonical); err != nil {
		return err
	}
	encoded, err := jsonwire.Encode(canonical)
	if err != nil {
		return err
	}
	signature := sha256.Sum256(encoded)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.issued.IsZero() {
		if value.Issued.Before(r.issued) || value.Issued.Equal(r.issued) && signature != r.signature {
			return errors.New("stale or conflicting Service publication")
		}
		if value.Issued.Equal(r.issued) {
			return nil
		}
	}
	r.current, r.issued, r.signature, r.observed = records, value.Issued, signature, now
	r.deadline = now.Mono + min(Lease, value.Until.Sub(now.Wall))
	return nil
}

// Records shortens validity using both clocks without changing the stored lease.
func (r *Receiver) Records(now catalog.Moment) []catalog.Record {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := now.Mono - r.observed.Mono
	difference := now.Wall.Sub(r.observed.Wall) - elapsed
	if r.issued.IsZero() || elapsed < 0 || now.Mono >= r.deadline || difference < -2*time.Second || difference > 2*time.Second {
		return nil
	}
	result := make([]catalog.Record, 0, len(r.current))
	for _, record := range r.current {
		if until := now.Wall.Add(r.deadline - now.Mono); until.Before(record.Expires) {
			record.Expires = until
		}
		if record.Expires.After(now.Wall) {
			result = append(result, record)
		}
	}
	return result
}

// API reuses HTTP framing and source admission on the publication listener only.
func (r *Receiver) API() gateway.Handler {
	bucket := gateway.NewBucket(2, 4)
	return func(_ context.Context, method, target string, data []byte) (int, []byte) {
		if method != http.MethodPost || target != "/v1/publications" {
			return 404, []byte(`{"error":"route"}`)
		}
		now := catalog.Now()
		if !bucket.Take(now.Mono, 1) {
			return 429, []byte(`{"error":"capacity"}`)
		}
		if err := r.Install(data, now); err != nil {
			return 400, []byte(`{"error":"publication"}`)
		}
		return 200, []byte(`{"accepted":true}`)
	}
}
