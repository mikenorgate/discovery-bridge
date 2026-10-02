package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
)

// ErrBusy signals bounded lookup admission rather than a negative DNS answer.
var ErrBusy = errors.New("lookup capacity exceeded")

// DecodeLookup accepts only the existing question-only lookup schema.
func DecodeLookup(data []byte) ([]responder.Question, error) {
	var value struct {
		Schema    int                  `json:"schema"`
		Questions []responder.Question `json:"questions"`
	}
	if err := jsonwire.Decode(data, MaxRequestBytes, &value); err != nil {
		return nil, err
	}
	if value.Schema != 1 || len(value.Questions) < 1 || len(value.Questions) > 16 {
		return nil, errors.New("bounded lookup questions required")
	}
	seen := make(map[responder.Question]bool)
	for index := range value.Questions {
		q := &value.Questions[index]
		if q.Class != dns.ClassINET || !catalog.LocalName(q.Name) {
			return nil, errors.New("lookup must be IN local")
		}
		switch q.Type {
		case dns.TypeA, dns.TypeAAAA, dns.TypePTR, dns.TypeSRV, dns.TypeTXT, dns.TypeANY:
		default:
			return nil, errors.New("unsupported lookup type")
		}
		q.Name = catalog.NameKey(q.Name)
		if seen[*q] {
			return nil, errors.New("duplicate lookup question")
		}
		seen[*q] = true
	}
	return value.Questions, nil
}

// Bucket enforces a monotonic token budget. Backwards time fails closed.
type Bucket struct {
	mu                  sync.Mutex
	rate, burst, tokens float64
	updated             time.Duration
	started, failed     bool
}

// NewBucket uses fixed process-owned rate and burst limits.
func NewBucket(rate, burst float64) *Bucket { return &Bucket{rate: rate, burst: burst, tokens: burst} }

// Take charges requests, including duplicates that will later be coalesced.
func (b *Bucket) Take(now time.Duration, cost int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cost < 1 || now < 0 || (b.started && now < b.updated) {
		b.failed = true
	}
	if b.failed {
		return false
	}
	if b.started {
		b.tokens = min(b.burst, b.tokens+(now-b.updated).Seconds()*b.rate)
	}
	b.updated, b.started = now, true
	if float64(cost) > b.tokens {
		return false
	}
	b.tokens -= float64(cost)
	return true
}

type pending struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

// Lookups coalesces bounded question demand over configured sources.
type Lookups struct {
	mu      sync.Mutex
	demand  func(context.Context, responder.Question) error
	pending map[responder.Question]*pending
	recent  map[responder.Question]time.Duration
	bucket  *Bucket
	closed  bool
}

// NewLookups wraps a LAN demand callback that owns source admission.
func NewLookups(demand func(context.Context, responder.Question) error) *Lookups {
	return &Lookups{demand: demand, pending: make(map[responder.Question]*pending), recent: make(map[responder.Question]time.Duration), bucket: NewBucket(32, 128)}
}

// Submit validates and coalesces work; disconnects cannot cancel shared demand.
func (l *Lookups) Submit(ctx context.Context, data []byte) (int, error) {
	questions, err := DecodeLookup(data)
	if err != nil {
		return 0, err
	}
	now := catalog.Now().Mono
	if !l.bucket.Take(now, len(questions)) {
		return 0, ErrBusy
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return 0, errors.New("lookup owner closed")
	}
	for key, end := range l.recent {
		if now >= end {
			delete(l.recent, key)
		}
	}
	var newQuestions []responder.Question
	for _, q := range questions {
		if l.pending[q] == nil && l.recent[q] == 0 {
			newQuestions = append(newQuestions, q)
		}
	}
	if len(l.pending)+len(newQuestions) > 64 {
		l.mu.Unlock()
		return 0, ErrBusy
	}
	for _, q := range newQuestions {
		work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		p := &pending{done: make(chan struct{}), cancel: cancel}
		l.pending[q] = p
		go func() {
			defer cancel()
			err := l.demand(work, q)
			l.mu.Lock()
			p.err = err
			delete(l.pending, q)
			l.recent[q] = catalog.Now().Mono + time.Second
			for len(l.recent) > 512 {
				for key := range l.recent {
					delete(l.recent, key)
					break
				}
			}
			close(p.done)
			l.mu.Unlock()
		}()
	}
	var waits []*pending
	for _, q := range questions {
		if p := l.pending[q]; p != nil {
			waits = append(waits, p)
		}
	}
	l.mu.Unlock()
	for _, p := range waits {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-p.done:
			if p.err != nil {
				return 0, p.err
			}
		}
	}
	return len(questions), nil
}

// Close cancels and joins all remaining LAN work.
func (l *Lookups) Close() {
	l.mu.Lock()
	l.closed = true
	var waits []*pending
	for _, p := range l.pending {
		p.cancel()
		waits = append(waits, p)
	}
	l.mu.Unlock()
	for _, p := range waits {
		<-p.done
	}
}
