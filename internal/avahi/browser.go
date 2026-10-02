package avahi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

// Query stays on one operator-approved interface and transport family.
type Query struct {
	Interface, Family int
	Name              string
	Type              uint16
}

// Event is a browser hint. It deliberately carries no expiry or renewable TTL.
type Event struct {
	Epoch         string
	Query         Query
	Record        observation.Record
	Added, Cached bool
}

type seenKey struct {
	path dbus.ObjectPath
	data string
}

// Browser owns one Avahi connection epoch. Next has one consumer; Watch, Follow
// and Retire may be called concurrently. Closing frees all connection-owned browsers.
type Browser struct {
	bus        *bus
	epoch      string
	links      map[int]observation.Link
	operations sync.Mutex
	mu         sync.Mutex
	paths      map[dbus.ObjectPath]Query
	queries    map[Query]dbus.ObjectPath
	seen       map[seenKey]dns.RR
	touched    map[Query]time.Time
	permanent  map[Query]bool
	deferred   uint64
}

// ConnectBrowser opens a local D-Bus connection and verifies a stable running Avahi.
func ConnectBrowser(ctx context.Context, path string, links map[int]observation.Link) (*Browser, error) {
	b, err := newBrowser(links)
	if err != nil {
		return nil, err
	}
	b.bus, err = connectBus(ctx, path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func newBrowser(links map[int]observation.Link) (*Browser, error) {
	if len(links) == 0 || len(links) > 64 {
		return nil, errors.New("explicit bounded LAN interfaces required")
	}
	links = maps.Clone(links)
	for index, link := range links {
		if index < 1 || link.Source == "" || link.Generation == "" || len(link.Families) == 0 || len(link.Families) > 2 {
			return nil, errors.New("LAN link requires index, identity, generation and families")
		}
		families := slices.Clone(link.Families)
		slices.Sort(families)
		if slices.ContainsFunc(families, func(f int) bool { return f != 4 && f != 6 }) || len(slices.Compact(families)) != len(families) {
			return nil, errors.New("LAN families must be distinct IPv4 or IPv6")
		}
		link.Families = families
		links[index] = link
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	return &Browser{epoch: hex.EncodeToString(token[:]), links: links,
		paths: make(map[dbus.ObjectPath]Query), queries: make(map[Query]dbus.ObjectPath),
		seen: make(map[seenKey]dns.RR), touched: make(map[Query]time.Time), permanent: make(map[Query]bool)}, nil
}

// Epoch identifies hints that must be discarded together after connection loss.
func (b *Browser) Epoch() string { return b.epoch }

// Err reports a failed observation epoch without exposing device identifiers.
func (b *Browser) Err() error {
	if b.bus == nil {
		return errors.New("avahi browser is not connected")
	}
	return b.bus.err()
}

// Close withdraws all browser ownership and joins the connection monitor.
func (b *Browser) Close() {
	if b.bus != nil {
		b.bus.close()
	}
}

func (b *Browser) normalize(query Query) (Query, error) {
	name, err := localName(query.Name)
	link, ok := b.links[query.Interface]
	if err != nil || !ok || !slices.Contains(link.Families, query.Family) || !observation.Supported(query.Type) {
		return Query{}, errors.New("unapproved Avahi query scope, name or record type")
	}
	query.Name = name
	return query, nil
}

// Watch coalesces demand. At the 1024-browser limit it defers new watches while
// keeping admitted observations alive; retirement can make room for a retry.
func (b *Browser) Watch(ctx context.Context, query Query) (bool, error) {
	query, err := b.normalize(query)
	if err != nil {
		return false, err
	}
	b.operations.Lock()
	defer b.operations.Unlock()
	if err := b.Err(); err != nil {
		return false, err
	}
	b.mu.Lock()
	if _, ok := b.queries[query]; ok {
		b.touched[query] = time.Now()
		b.mu.Unlock()
		return true, nil
	}
	if len(b.queries) >= 1024 {
		b.deferred++
		b.mu.Unlock()
		return false, nil
	}
	b.mu.Unlock()
	name, err := avahiName(query.Name)
	if err != nil {
		return false, err
	}
	protocol := int32(0)
	if query.Family == 6 {
		protocol = 1
	}
	var path dbus.ObjectPath
	err = b.bus.call(ctx, "/", server2+".RecordBrowserPrepare", int32(query.Interface), protocol, name, uint16(dns.ClassINET), query.Type, uint32(2)).Store(&path)
	if err == nil && (!path.IsValid() || path == "/") {
		err = errors.New("invalid Avahi browser path")
	}
	if err == nil {
		b.mu.Lock()
		if _, reused := b.paths[path]; reused {
			err = errors.New("avahi reused an active browser path")
		} else {
			// Install routing before Start can deliver its first cached signal.
			b.paths[path], b.queries[query], b.touched[query] = query, path, time.Now()
		}
		b.mu.Unlock()
	}
	if err == nil {
		err = b.bus.call(ctx, path, browserInterface+".Start").Err
	}
	if err != nil {
		b.bus.fail(errors.New("avahi browser setup failed; discard observation epoch"))
		return false, err
	}
	return true, b.Err()
}

// Seed asks the standard DNS-SD enumeration question on every approved family.
func (b *Browser) Seed(ctx context.Context) error {
	indices := slices.Sorted(maps.Keys(b.links))
	for _, index := range indices {
		for _, family := range b.links[index].Families {
			query := Query{index, family, catalog.Enumeration, dns.TypePTR}
			admitted, err := b.Watch(ctx, query)
			if err != nil {
				return err
			}
			if !admitted {
				return errors.New("avahi seed browser capacity exceeded")
			}
			b.mu.Lock()
			b.permanent[query] = true
			b.mu.Unlock()
		}
	}
	return nil
}

func dependencies(query Query, rr dns.RR) []Query {
	var target string
	var types []uint16
	switch value := rr.(type) {
	case *dns.PTR:
		target, types = value.Ptr, []uint16{dns.TypeSRV, dns.TypeTXT}
		if query.Name == catalog.Enumeration {
			types = []uint16{dns.TypePTR}
		}
	case *dns.SRV:
		target, types = value.Target, []uint16{dns.TypeA, dns.TypeAAAA}
	}
	var result []Query
	for _, kind := range types {
		result = append(result, Query{query.Interface, query.Family, catalog.NameKey(target), kind})
	}
	return result
}

// Follow browses dependencies on the observation's original interface and family.
func (b *Browser) Follow(ctx context.Context, event Event) error {
	if event.Epoch != b.epoch || !event.Added {
		return nil
	}
	for _, query := range dependencies(event.Query, event.Record.RR) {
		if _, err := b.Watch(ctx, query); err != nil {
			return err
		}
	}
	return nil
}

// Retire frees only empty, idle browsers that no active record still needs.
func (b *Browser) Retire(ctx context.Context) error {
	b.operations.Lock()
	defer b.operations.Unlock()
	if err := b.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	needed, active := make(map[Query]bool), make(map[dbus.ObjectPath]bool)
	for key, rr := range b.seen {
		active[key.path] = true
		for _, query := range dependencies(b.paths[key.path], rr) {
			needed[query] = true
		}
	}
	var retired []dbus.ObjectPath
	for query, path := range b.queries {
		if !b.permanent[query] && !needed[query] && !active[path] && time.Since(b.touched[query]) >= 120*time.Second {
			// Remove routing first so late signals cannot revive a retired watch.
			delete(b.paths, path)
			delete(b.queries, query)
			delete(b.touched, query)
			retired = append(retired, path)
		}
	}
	b.mu.Unlock()
	for _, path := range retired {
		if err := b.bus.call(ctx, path, browserInterface+".Free").Err; err != nil {
			b.bus.fail(errors.New("avahi browser retirement failed"))
			return err
		}
	}
	return b.Err()
}

// Next returns one admitted hint; failure always takes precedence over queued hints.
func (b *Browser) Next(ctx context.Context) (Event, error) {
	for {
		if err := b.Err(); err != nil {
			return Event{}, err
		}
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-b.bus.failed:
			return Event{}, b.Err()
		case signal := <-b.bus.signals:
			b.mu.Lock()
			event, admitted, err := b.event(signal)
			b.mu.Unlock()
			if err != nil {
				b.bus.fail(errors.New("invalid or overflowing Avahi event stream"))
				return Event{}, err
			}
			if err := b.Err(); err != nil {
				return Event{}, err
			}
			if admitted {
				return event, nil
			}
		}
	}
}

func (b *Browser) event(signal *dbus.Signal) (Event, bool, error) {
	query, ok := b.paths[signal.Path]
	if !ok || !strings.HasPrefix(signal.Name, browserInterface+".") {
		return Event{}, false, nil
	}
	if signal.Name == browserInterface+".Failure" {
		return Event{}, false, errors.New("avahi record browser failed")
	}
	added := signal.Name == browserInterface+".ItemNew"
	if !added && signal.Name != browserInterface+".ItemRemove" {
		return Event{}, false, nil
	}
	var index, protocol int32
	var name string
	var class, kind uint16
	var raw []byte
	var flags uint32
	if err := dbus.Store(signal.Body, &index, &protocol, &name, &class, &kind, &raw, &flags); err != nil {
		return Event{}, false, err
	}
	family := 4
	if protocol == 1 {
		family = 6
	} else if protocol != 0 {
		return Event{}, false, errors.New("invalid Avahi transport family")
	}
	name, err := localName(name)
	if err != nil || int(index) != query.Interface || family != query.Family || name != query.Name || kind != query.Type || class != dns.ClassINET {
		return Event{}, false, errors.New("avahi browser event scope mismatch")
	}
	// A shared enumeration PTR can be LOCAL because our publisher registers the
	// same type. It remains only a hint: independent remote wire evidence is required.
	enumeration := kind == dns.TypePTR && name == catalog.Enumeration
	if flags&(2|16|32) != 0 || flags&8 != 0 && !enumeration || flags&4 == 0 {
		return Event{}, false, nil
	}
	rr, err := rawRecord(name, kind, raw)
	if err != nil {
		return Event{}, false, err
	}
	key := seenKey{signal.Path, (catalog.Answer{RR: rr}).Key()}
	if added {
		b.seen[key] = rr
		if len(b.seen) > catalog.MaxRecords {
			return Event{}, false, errors.New("avahi hint capacity exceeded")
		}
	} else if _, exists := b.seen[key]; !exists {
		return Event{}, false, nil
	} else {
		delete(b.seen, key)
	}
	link := b.links[query.Interface]
	return Event{Epoch: b.epoch, Query: query,
		Record: observation.Record{Source: link.Source, Generation: link.Generation, Family: family, RR: rr},
		Added:  added, Cached: flags&1 != 0}, true, nil
}

// Counts reports resource use without recording queries or device identities.
func (b *Browser) Counts() (watches, hints int, deferred uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.queries), len(b.seen), b.deferred
}
