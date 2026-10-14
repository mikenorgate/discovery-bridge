// Package native provides source-qualified, wire-backed discovery queries.
// It has no authority to synthesize addresses or publish records.
package native

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

// ErrBusy means the bounded native query budget has been exhausted.
var ErrBusy = errors.New("native: query capacity exceeded")

// ErrUnavailable means no current source generation can answer the question.
var ErrUnavailable = errors.New("native: observation epoch unavailable")

// Question contains only an admitted source and a DNS question, never client data.
type Question struct {
	Source string
	DNS    dns.Question
}

// Result is a copied native answer and its same-source dependencies.
type Result struct {
	Epoch   string
	Records []dns.RR
}

// Start opens one bounded multicast interest. Its returned cleanup releases only
// that interest; Avahi may still have unrelated consumers of the same question.
type Start func(context.Context, Question) (func() error, error)

type pending struct {
	done   chan struct{}
	cancel context.CancelFunc
	users  int
	result Result
	err    error
}

// Resolver coalesces queries within one collector epoch and retains wire TTLs.
type Resolver struct {
	mu        sync.Mutex
	epoch     string
	sources   map[string][]netip.Prefix
	cache     *observation.Cache
	start     Start
	changed   chan struct{}
	closed    chan struct{}
	pending   map[Question]*pending
	perSource map[string]int
	workers   sync.WaitGroup
	isClosed  bool
}

// New validates immutable source admission. Close must be called before the
// underlying multicast resources for this epoch are destroyed.
func New(epoch string, sources map[string][]netip.Prefix, start Start) (*Resolver, error) {
	if epoch == "" || len(sources) == 0 || len(sources) > 12 || start == nil {
		return nil, errors.New("native: explicit epoch, sources and query owner required")
	}
	copySources := make(map[string][]netip.Prefix, len(sources))
	for source, prefixes := range sources {
		if source == "" || len(source) > 128 || len(prefixes) == 0 || len(prefixes) > 128 {
			return nil, errors.New("native: invalid source admission")
		}
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 {
				return nil, errors.New("native: invalid source prefix")
			}
		}
		copySources[source] = slices.Clone(prefixes)
	}
	return &Resolver{
		epoch: epoch, sources: copySources, cache: observation.New(), start: start,
		changed: make(chan struct{}), closed: make(chan struct{}),
		pending: make(map[Question]*pending), perSource: make(map[string]int),
	}, nil
}

// Close withdraws authority, cancels all interests and joins their owners.
func (r *Resolver) Close() {
	r.mu.Lock()
	if !r.isClosed {
		r.isClosed = true
		close(r.closed)
		for _, operation := range r.pending {
			operation.cancel()
		}
	}
	r.mu.Unlock()
	r.workers.Wait()
}

// Ingest accepts only already validated wire observations from this epoch.
func (r *Resolver) Ingest(records []observation.Record, received, now time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed {
		return ErrUnavailable
	}
	selected := make([]observation.Record, 0, len(records))
	for _, record := range records {
		if _, ok := r.sources[record.Source]; !ok {
			continue
		}
		if record.Generation != r.epoch {
			return ErrUnavailable
		}
		selected = append(selected, record)
	}
	if err := r.cache.IngestAt(selected, received, now); err != nil {
		return err
	}
	close(r.changed)
	r.changed = make(chan struct{})
	return nil
}

func (r *Resolver) normalize(question Question) (Question, error) {
	prefixes, ok := r.sources[question.Source]
	if !ok || !dnswire.LocalOrReverse(question.DNS.Name, prefixes) || question.DNS.Qclass != dns.ClassINET {
		return Question{}, errors.New("native: unapproved source or question")
	}
	if question.DNS.Qtype == 0 || question.DNS.Qtype >= dns.TypeTKEY && question.DNS.Qtype <= dns.TypeMAILA {
		return Question{}, errors.New("native: unsupported question type")
	}
	question.DNS.Name = catalog.NameKey(question.DNS.Name)
	return question, nil
}

// Query answers immediately from fresh wire evidence or shares a six-second
// multicast lookup. One caller's cancellation cannot cancel another's interest.
func (r *Resolver) Query(ctx context.Context, question Question) (Result, error) {
	question, err := r.normalize(question)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
retry:
	r.mu.Lock()
	if r.isClosed {
		r.mu.Unlock()
		return Result{}, ErrUnavailable
	}
	result, answered, err := r.lookup(question)
	if err != nil || answered {
		r.mu.Unlock()
		return result, err
	}
	operation := r.pending[question]
	if operation != nil && operation.users == 0 {
		// The last caller cancelled this interest. Join its cleanup before
		// starting again rather than handing a new caller a cancelled operation.
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-operation.done:
			goto retry
		}
	}
	if operation == nil {
		if len(r.pending) >= 64 || r.perSource[question.Source] >= 16 {
			r.mu.Unlock()
			return Result{}, ErrBusy
		}
		shared, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Second)
		operation = &pending{done: make(chan struct{}), cancel: cancel}
		r.pending[question] = operation
		r.perSource[question.Source]++
		r.workers.Go(func() { r.resolve(shared, question, operation) })
	}
	operation.users++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		operation.users--
		if operation.users == 0 {
			operation.cancel()
		}
		r.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-r.closed:
		return Result{}, ErrUnavailable
	case <-operation.done:
		return copyResult(operation.result), operation.err
	}
}

func copyResult(result Result) Result {
	copy := Result{Epoch: result.Epoch, Records: make([]dns.RR, 0, len(result.Records))}
	for _, record := range result.Records {
		copy.Records = append(copy.Records, dns.Copy(record))
	}
	return copy
}

func (r *Resolver) lookup(question Question) (Result, bool, error) {
	records, err := r.cache.NativeRecords(catalog.Now().Mono)
	if err != nil {
		return Result{}, false, err
	}
	result := Result{Epoch: r.epoch, Records: []dns.RR{}}
	wanted := map[string]bool{question.DNS.Name: true}
	answered := false
	for _, record := range records {
		if record.Source != question.Source || catalog.NameKey(record.RR.Header().Name) != question.DNS.Name {
			continue
		}
		kind := record.RR.Header().Rrtype
		if kind == question.DNS.Qtype || question.DNS.Qtype == dns.TypeANY || kind == dns.TypeCNAME {
			answered = true
		}
		if denial, ok := record.RR.(*dns.NSEC); ok && question.DNS.Qtype != dns.TypeANY {
			if !slices.Contains(denial.TypeBitMap, question.DNS.Qtype) && !slices.Contains(denial.TypeBitMap, dns.TypeCNAME) {
				answered = true
			}
		}
	}
	// Include complete same-source dependency chains, never unrelated sources.
	for range 8 {
		changed := false
		for _, record := range records {
			if record.Source != question.Source || !wanted[catalog.NameKey(record.RR.Header().Name)] {
				continue
			}
			for _, field := range dnswire.NameFields(record.RR) {
				key := catalog.NameKey(*field)
				if !wanted[key] && dnswire.LocalOrReverse(*field, r.sources[question.Source]) {
					wanted[key], changed = true, true
				}
			}
		}
		if !changed {
			break
		}
	}
	for _, record := range records {
		if record.Source == question.Source && wanted[catalog.NameKey(record.RR.Header().Name)] {
			result.Records = append(result.Records, record.RR)
			if len(result.Records) > 256 {
				return Result{}, false, ErrBusy
			}
		}
	}
	return result, answered, nil
}

func (r *Resolver) resolve(ctx context.Context, question Question, operation *pending) {
	defer operation.cancel()
	cleanup, err := r.start(ctx, question)
	result := Result{Epoch: r.epoch, Records: []dns.RR{}}
	// Avahi owns typed retransmission. ANY uses the existing wire sender at 0,1,3s.
	retry := time.NewTimer(time.Second)
	defer retry.Stop()
	var retried int
	for err == nil {
		r.mu.Lock()
		var answered bool
		result, answered, err = r.lookup(question)
		changed := r.changed
		r.mu.Unlock()
		if answered || err != nil {
			break
		}
		select {
		case <-r.closed:
			err = ErrUnavailable
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				err = ctx.Err()
			}
			goto finished
		case <-changed:
		case <-retry.C:
			if question.DNS.Qtype == dns.TypeANY && retried < 2 {
				var release func() error
				release, err = r.start(ctx, question)
				if release != nil {
					err = errors.Join(err, release())
				}
				retried++
				if retried == 1 {
					retry.Reset(2 * time.Second)
				}
			}
		}
	}
finished:
	if cleanup != nil {
		err = errors.Join(err, cleanup())
	}
	r.mu.Lock()
	if r.isClosed {
		err = ErrUnavailable
	}
	operation.result, operation.err = result, err
	delete(r.pending, question)
	r.perSource[question.Source]--
	close(operation.done)
	r.mu.Unlock()
}
