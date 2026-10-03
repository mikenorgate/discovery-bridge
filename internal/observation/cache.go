// Package observation correlates Avahi hints with independently expiring wire evidence.
package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

// Record retains the LAN link generation and transport family of an observation.
type Record struct {
	Source, Generation string
	Family             int
	RR                 dns.RR
	Flush              bool
}

type key struct {
	source, generation string
	family             int
	data               string
}

func (r Record) key() key {
	return key{r.Source, r.Generation, r.Family, (catalog.Answer{RR: r.RR}).Key()}
}

func (k key) withoutFamily() key { k.family = 0; return k }

type set struct {
	source, generation string
	rrset              catalog.RRSet
}

func (r Record) set() set { return set{r.Source, r.Generation, (catalog.Answer{RR: r.RR}).Set()} }

type evidence struct {
	record             Record
	received, deadline time.Duration
}

type flush struct {
	received time.Duration
	present  map[string]bool
}

// Cache belongs to one collector epoch; its caller serializes all access.
// Avahi events alone cannot create records or extend their wire TTLs.
type Cache struct {
	wire    map[key]evidence
	hints   map[key]map[string]bool
	flushed map[set]flush
	last    time.Duration
	failed  bool
}

// New starts an empty observation epoch with the existing 4096-record bound.
func New() *Cache {
	return &Cache{wire: make(map[key]evidence), hints: make(map[key]map[string]bool), flushed: make(map[set]flush)}
}

func (c *Cache) fail() {
	c.failed = true
	clear(c.wire)
	clear(c.hints)
	clear(c.flushed)
}

func (c *Cache) clock(now time.Duration) error {
	if now < 0 || now < c.last {
		c.fail()
	}
	if c.failed {
		return errors.New("observation epoch requires fresh bootstrap")
	}
	c.last = now
	for key, value := range c.wire {
		if now >= value.deadline {
			delete(c.wire, key)
		}
	}
	for key, value := range c.flushed {
		if now-value.received >= catalog.Lease {
			delete(c.flushed, key)
		}
	}
	return nil
}

// Ingest atomically applies one packet's additions, flushes and goodbye grace.
func (c *Cache) Ingest(records []Record, now time.Duration) error {
	return c.IngestAt(records, now, now)
}

// IngestAt retains the receive timestamp when a collector queues observations.
// Processing delay cannot renew wire TTLs, and late packets cannot replace newer
// evidence or invalidate its cache-flush protection.
func (c *Cache) IngestAt(records []Record, received, now time.Duration) error {
	if err := c.clock(now); err != nil {
		return err
	}
	if received < 0 || received > now {
		return errors.New("invalid wire receive timestamp")
	}
	if now-received >= catalog.Lease {
		return nil // Queued traffic older than a producer lease has no authority.
	}
	candidate := maps.Clone(c.wire)
	flushed := maps.Clone(c.flushed)
	flushing := make(map[set]bool)
	members := make(map[set]map[string]bool)
	present := make(map[key]bool)
	for _, r := range records {
		if r.RR == nil || r.Source == "" || r.Generation == "" || (r.Family != 4 && r.Family != 6) {
			return errors.New("invalid wire evidence")
		}
		if r.RR.Header().Ttl > 0 {
			present[r.key().withoutFamily()] = true
			rrset := r.set()
			if members[rrset] == nil {
				members[rrset] = make(map[string]bool)
			}
			members[rrset][r.key().data] = true
			if r.Flush {
				flushing[r.set()] = true
			}
		}
	}
	for key, value := range candidate {
		if flushing[value.record.set()] && !present[key.withoutFamily()] && received-value.received >= time.Second {
			value.deadline = min(value.deadline, received+time.Second)
			candidate[key] = value
		}
	}
	for rrset := range flushing {
		if previous, ok := flushed[rrset]; ok && previous.received > received {
			continue
		}
		flushed[rrset] = flush{received, members[rrset]}
	}
	for _, r := range records {
		if r.RR.Header().Ttl == 0 {
			for key, value := range candidate {
				if key.withoutFamily() == r.key().withoutFamily() && value.received <= received {
					value.deadline = min(value.deadline, received+time.Second)
					candidate[key] = value
				}
			}
		} else {
			if previous, ok := candidate[r.key()]; ok && previous.received > received {
				continue
			}
			deadline := received + time.Duration(min(r.RR.Header().Ttl, 86400))*time.Second
			if latest, ok := flushed[r.set()]; ok && latest.received > received {
				if latest.present[r.key().data] {
					continue // The newer packet's TTL supersedes this queued copy.
				}
				if latest.received-received >= time.Second {
					deadline = min(deadline, latest.received+time.Second)
				}
			}
			r.RR = dns.Copy(r.RR)
			candidate[r.key()] = evidence{r, received, deadline}
		}
	}
	for key, value := range candidate {
		if value.deadline <= now {
			delete(candidate, key)
		}
	}
	flushMembers := 0
	for _, latest := range flushed {
		flushMembers += len(latest.present)
	}
	if len(candidate) > catalog.MaxRecords || flushMembers > catalog.MaxRecords {
		c.fail()
		return errors.New("wire observation capacity exceeded")
	}
	c.wire = candidate
	c.flushed = flushed
	return nil
}

// Hint admits or removes a hint for an exact source, generation and family.
func (c *Cache) Hint(epoch string, r Record, added bool) error {
	if c.failed || epoch == "" || r.RR == nil || r.Source == "" || r.Generation == "" || (r.Family != 4 && r.Family != 6) {
		return errors.New("invalid Avahi hint epoch")
	}
	k := r.key()
	if added {
		if c.hints[k] == nil {
			if len(c.hints) >= catalog.MaxRecords {
				c.fail()
				return errors.New("hint capacity exceeded")
			}
			c.hints[k] = make(map[string]bool)
		}
		c.hints[k][epoch] = true
	} else {
		delete(c.hints[k], epoch)
		if len(c.hints[k]) == 0 {
			delete(c.hints, k)
		}
	}
	return nil
}

// ForgetEpoch withdraws hints without renewing retained wire observations.
func (c *Cache) ForgetEpoch(epoch string) {
	for key, epochs := range c.hints {
		delete(epochs, epoch)
		if len(epochs) == 0 {
			delete(c.hints, key)
		}
	}
}

// ForgetLink withdraws all observations for a replaced link generation.
func (c *Cache) ForgetLink(source, generation string) {
	for key := range c.flushed {
		if key.source == source && key.generation == generation {
			delete(c.flushed, key)
		}
	}
	for key := range c.wire {
		if key.source == source && key.generation == generation {
			delete(c.wire, key)
		}
	}
	for key := range c.hints {
		if key.source == source && key.generation == generation {
			delete(c.hints, key)
		}
	}
}

// Records floors the shortest correlated lifetime, independent of IP transport.
func (c *Cache) Records(now catalog.Moment) ([]catalog.Record, error) {
	if err := c.clock(now.Mono); err != nil {
		return nil, err
	}
	result := make(map[string]catalog.Record)
	for key, value := range c.wire {
		ttl := min((value.deadline-now.Mono)/time.Second, catalog.MaxTTL)
		if len(c.hints[key]) == 0 || ttl < 1 {
			continue
		}
		rr := value.record.RR
		hash := sha256.Sum256([]byte(key.source + "\x00" + key.data))
		id := hex.EncodeToString(hash[:])
		r := catalog.Record{ID: id, Name: rr.Header().Name, Type: dns.TypeToString[rr.Header().Rrtype], Data: strings.TrimPrefix(rr.String(), rr.Header().String()), Source: key.source, Expires: now.Wall.Add(ttl * time.Second)}
		if old, ok := result[id]; !ok || r.Expires.Before(old.Expires) {
			result[id] = r
		}
	}
	values := slices.Collect(maps.Values(result))
	slices.SortFunc(values, func(a, b catalog.Record) int { return strings.Compare(a.ID, b.ID) })
	return values, nil
}

// Counts reports bounded wire and hint counts without device identifiers.
func (c *Cache) Counts() (wire, hints int) { return len(c.wire), len(c.hints) }
