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

// Cache belongs to one collector epoch; its caller serializes all access.
// Avahi events alone cannot create records or extend their wire TTLs.
type Cache struct {
	wire   map[key]evidence
	hints  map[key]map[string]bool
	last   time.Duration
	failed bool
}

// New starts an empty observation epoch with the existing 4096-record bound.
func New() *Cache {
	return &Cache{wire: make(map[key]evidence), hints: make(map[key]map[string]bool)}
}

func (c *Cache) fail() {
	c.failed = true
	clear(c.wire)
	clear(c.hints)
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
	return nil
}

// Ingest atomically applies one packet's additions, flushes and goodbye grace.
func (c *Cache) Ingest(records []Record, now time.Duration) error {
	if err := c.clock(now); err != nil {
		return err
	}
	candidate := maps.Clone(c.wire)
	flushing := make(map[set]bool)
	present := make(map[key]bool)
	for _, r := range records {
		if r.RR == nil || r.Source == "" || r.Generation == "" || (r.Family != 4 && r.Family != 6) {
			return errors.New("invalid wire evidence")
		}
		if r.RR.Header().Ttl > 0 {
			present[r.key().withoutFamily()] = true
			if r.Flush {
				flushing[r.set()] = true
			}
		}
	}
	for key, value := range candidate {
		if flushing[value.record.set()] && !present[key.withoutFamily()] && now-value.received >= time.Second {
			value.deadline = min(value.deadline, now+time.Second)
			candidate[key] = value
		}
	}
	for _, r := range records {
		if r.RR.Header().Ttl == 0 {
			for key, value := range candidate {
				if key.withoutFamily() == r.key().withoutFamily() {
					value.deadline = min(value.deadline, now+time.Second)
					candidate[key] = value
				}
			}
		} else {
			r.RR = dns.Copy(r.RR)
			candidate[r.key()] = evidence{r, now, now + time.Duration(min(r.RR.Header().Ttl, 86400))*time.Second}
		}
	}
	if len(candidate) > catalog.MaxRecords {
		c.fail()
		return errors.New("wire observation capacity exceeded")
	}
	c.wire = candidate
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
