package avahi

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

const groupInterface = service + ".EntryGroup"

// Intent carries a complete admitted group and an absolute Linux monotonic lease.
type Intent struct {
	Interface, Family int
	Deadline          time.Duration
	Records           []catalog.Answer
}

// Goodbye sends only this owner's previously committed record signature.
type Goodbye func(context.Context, int, int, []catalog.Answer) error

type groupKey struct{ index, family int }
type group struct {
	path      dbus.ObjectPath
	records   []catalog.Answer
	deadline  time.Duration
	committed bool
}

// Publisher owns one independent Avahi connection. Its lease monitor continues
// while producer reads or reconciliation stall; ownership loss closes D-Bus and
// withdraws the epoch. A fresh connection is required after that failure.
type Publisher struct {
	bus        *bus
	links      map[int]observation.Link
	goodbye    Goodbye
	operations sync.Mutex
	mu         sync.Mutex
	groups     map[groupKey]group
	conflicts  map[string]bool
	done       chan struct{}
}

// ConnectPublisher verifies Avahi and starts independent lease supervision.
func ConnectPublisher(ctx context.Context, path string, links map[int]observation.Link, goodbye Goodbye) (*Publisher, error) {
	links, err := copyLinks(links)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, link := range links {
		count += len(link.Families)
	}
	if count > 12 || goodbye == nil {
		return nil, errors.New("bounded publication links and scoped goodbye sender required")
	}
	b, err := connectBus(ctx, path)
	if err != nil {
		return nil, err
	}
	p := &Publisher{bus: b, links: links, goodbye: goodbye, groups: make(map[groupKey]group), conflicts: make(map[string]bool), done: make(chan struct{})}
	go p.monitor()
	return p, nil
}

// Err reports loss of the independent publication epoch.
func (p *Publisher) Err() error { return p.bus.err() }

// Failed wakes the IPC owner on expiry, conflict or Avahi loss.
func (p *Publisher) Failed() <-chan struct{} { return p.bus.failed }

// Conflicts returns canonical unique names from a conflicting entry group.
func (p *Publisher) Conflicts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Sorted(maps.Keys(p.conflicts))
}

func (p *Publisher) monitor() {
	defer close(p.done)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	last := catalog.Now().Mono
	for {
		select {
		case <-p.bus.failed:
			return
		case signal := <-p.bus.signals:
			if signal.Name != groupInterface+".StateChanged" {
				continue
			}
			var state int32
			var detail string
			if err := dbus.Store(signal.Body, &state, &detail); err != nil {
				p.bus.fail(errors.New("invalid Avahi publication event"))
				continue
			}
			if state == 3 || state == 4 {
				p.mu.Lock()
				known := false
				for _, group := range p.groups {
					if group.path != signal.Path {
						continue
					}
					known = true
					for _, record := range group.records {
						if record.Unique {
							p.conflicts[catalog.NameKey(record.RR.Header().Name)] = true
						}
					}
				}
				p.mu.Unlock()
				if known {
					p.bus.fail(errors.New("avahi publication ownership conflict"))
				}
			}
		case <-ticker.C:
			now := catalog.Now().Mono
			invalid := now < 0 || now < last
			last = now
			p.mu.Lock()
			for _, group := range p.groups {
				invalid = invalid || now >= group.deadline
			}
			p.mu.Unlock()
			if invalid {
				p.bus.fail(errors.New("independent publication lease expired"))
			}
		}
	}
}

func signature(records []catalog.Answer) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		unique := "0"
		if record.Unique {
			unique = "1"
		}
		result = append(result, record.Key()+unique)
	}
	slices.Sort(result)
	return result
}

func cloneAnswers(records []catalog.Answer) []catalog.Answer {
	result := slices.Clone(records)
	for i := range result {
		result[i].RR = dns.Copy(result[i].RR)
	}
	return result
}

func (p *Publisher) validate(intents []Intent, now time.Duration) (map[groupKey]Intent, error) {
	if len(intents) > 12 {
		return nil, errors.New("publication group budget exceeded")
	}
	desired := make(map[groupKey]Intent)
	budget := 0
	for _, intent := range intents {
		link, ok := p.links[intent.Interface]
		key := groupKey{intent.Interface, intent.Family}
		if _, duplicate := desired[key]; duplicate || !ok || !slices.Contains(link.Families, intent.Family) || intent.Deadline <= now || intent.Deadline-now > 30*time.Second {
			return nil, errors.New("invalid publication group scope or deadline")
		}
		budget += len(intent.Records)
		if budget > catalog.MaxRecords {
			return nil, errors.New("publication record budget exceeded")
		}
		for _, record := range intent.Records {
			if record.RR == nil || !observation.Supported(record.RR.Header().Rrtype) || !catalog.LocalName(record.RR.Header().Name) {
				return nil, errors.New("invalid admitted publication record")
			}
		}
		intent.Records = cloneAnswers(intent.Records)
		desired[key] = intent
	}
	return desired, nil
}

// phase runs at most twelve independent groups concurrently. Calls within a
// group retain their order. The old lease bounds removal; the fresh lease then
// bounds creation, so a completed withdrawal cannot constrain its replacement.
func (p *Publisher) phase(ctx context.Context, until time.Duration, operations []func(context.Context) error) error {
	delay := until - catalog.Now().Mono
	if delay <= 0 {
		p.bus.fail(errors.New("publication lease expired before reconciliation"))
		return p.Err()
	}
	bounded, cancel := context.WithTimeout(ctx, min(delay, 3*time.Second))
	defer cancel()
	stop := context.AfterFunc(bounded, func() { p.bus.fail(errors.New("publication reconciliation exceeded lease budget")) })
	defer stop()
	var wg sync.WaitGroup
	var first error
	var failure sync.Once
	for _, operation := range operations {
		wg.Go(func() {
			if err := operation(bounded); err != nil {
				failure.Do(func() { first = err; p.bus.fail(errors.New("publication reconciliation failed")); cancel() })
			}
		})
	}
	wg.Wait()
	if first != nil {
		return first
	}
	return p.Err()
}

// Reconcile renews unchanged groups and replaces others within old and new leases.
// The caller must first validate persistent ownership and graph coherence at IPC.
func (p *Publisher) Reconcile(ctx context.Context, intents []Intent) error {
	p.operations.Lock()
	defer p.operations.Unlock()
	if err := p.Err(); err != nil {
		return err
	}
	now := catalog.Now().Mono
	desired, err := p.validate(intents, now)
	if err != nil {
		return err
	}
	deadline := now + 3*time.Second
	for _, intent := range intents {
		deadline = min(deadline, intent.Deadline)
	}
	var remove []func(context.Context) error
	p.mu.Lock()
	for key, previous := range p.groups {
		intent, exists := desired[key]
		if exists && slices.Equal(signature(previous.records), signature(intent.Records)) {
			previous.deadline = intent.Deadline
			p.groups[key] = previous
			continue
		}
		deadline = min(deadline, previous.deadline)
		remove = append(remove, func(ctx context.Context) error {
			if err := p.bus.call(ctx, previous.path, groupInterface+".Reset").Err; err != nil {
				return err
			}
			if err := p.bus.call(ctx, previous.path, groupInterface+".Free").Err; err != nil {
				return err
			}
			if previous.committed {
				if err := p.goodbye(ctx, key.index, key.family, previous.records); err != nil {
					return err
				}
			}
			p.mu.Lock()
			delete(p.groups, key)
			p.mu.Unlock()
			return nil
		})
	}
	p.mu.Unlock()
	if err := p.phase(ctx, deadline, remove); err != nil {
		return err
	}
	deadline = catalog.Now().Mono + 3*time.Second
	var add []func(context.Context) error
	for key, intent := range desired {
		deadline = min(deadline, intent.Deadline)
		if len(intent.Records) == 0 {
			continue
		}
		p.mu.Lock()
		_, exists := p.groups[key]
		p.mu.Unlock()
		if exists {
			continue
		}
		add = append(add, func(ctx context.Context) error {
			var path dbus.ObjectPath
			if err := p.bus.call(ctx, "/", server+".EntryGroupNew").Store(&path); err != nil {
				return err
			}
			if !path.IsValid() || path == "/" {
				return errors.New("invalid Avahi entry group path")
			}
			p.mu.Lock()
			p.groups[key] = group{path: path, records: intent.Records, deadline: intent.Deadline}
			p.mu.Unlock()
			protocol := int32(0)
			if key.family == 6 {
				protocol = 1
			}
			for _, record := range intent.Records {
				name, err := avahiName(record.RR.Header().Name)
				if err != nil {
					return err
				}
				raw, err := rdata(record.RR)
				if err != nil {
					return err
				}
				flags := uint32(0)
				if record.Unique {
					flags = 9
				}
				if err := p.bus.call(ctx, path, groupInterface+".AddRecord", int32(key.index), protocol, flags, name, uint16(dns.ClassINET), record.RR.Header().Rrtype, uint32(1), raw).Err; err != nil {
					return err
				}
			}
			if err := p.bus.call(ctx, path, groupInterface+".Commit").Err; err != nil {
				return err
			}
			p.mu.Lock()
			current := p.groups[key]
			current.committed = true
			p.groups[key] = current
			p.mu.Unlock()
			return nil
		})
	}
	return p.phase(ctx, deadline, add)
}

// Clear withdraws this producer's complete publication while keeping healthy Avahi.
func (p *Publisher) Clear(ctx context.Context) error { return p.Reconcile(ctx, nil) }

// Close drops Avahi ownership first, sends scoped goodbyes for committed groups,
// and joins the independent monitor. Goodbye failures cannot keep ownership alive.
func (p *Publisher) Close(ctx context.Context) error {
	p.bus.close()
	<-p.done
	p.operations.Lock()
	defer p.operations.Unlock()
	p.mu.Lock()
	groups := p.groups
	p.groups = make(map[groupKey]group)
	p.mu.Unlock()
	var errs []error
	for key, group := range groups {
		if group.committed {
			errs = append(errs, p.goodbye(ctx, key.index, key.family, group.records))
		}
	}
	return errors.Join(errs...)
}

// Counts reports publication use without device identifiers.
func (p *Publisher) Counts() (groups, records int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, group := range p.groups {
		records += len(group.records)
	}
	return len(p.groups), records
}
