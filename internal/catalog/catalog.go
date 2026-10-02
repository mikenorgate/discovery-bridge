// Package catalog maintains leased DNS records and coherent discovery views.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"golang.org/x/sys/unix"
)

const (
	MaxBytes    = 1_048_576
	MaxRecords  = 4096
	MaxTTL      = 30
	Lease       = 30 * time.Second
	ClockSkew   = 5 * time.Second
	Enumeration = "_services._dns-sd._udp.local."
)

// Moment carries wall time and the shared Linux monotonic clock independently.
type Moment struct {
	Wall time.Time
	Mono time.Duration
}

// Now samples clocks used for producer and record deadlines.
func Now() Moment {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(err) // Linux monotonic time is a required runtime facility.
	}
	return Moment{Wall: time.Now().UTC(), Mono: time.Duration(ts.Nano())}
}

// Record retains an observed source and independent expiry in the v1/v2 protocol.
type Record struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Data     string    `json:"data"`
	Source   string    `json:"source_link"`
	Expires  time.Time `json:"expires_at"`
	NativeID string    `json:"native_id,omitempty"`
}

// RR parses the record's canonical DNS representation with an explicit TTL.
func (r Record) RR(ttl uint32) (dns.RR, error) {
	return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", r.Name, ttl, r.Type, r.Data))
}

// Snapshot is a full replacement; omitted records are withdrawn.
type Snapshot struct {
	Schema   int       `json:"schema"`
	Epoch    string    `json:"epoch"`
	Revision int64     `json:"revision"`
	Issued   time.Time `json:"issued_at"`
	Until    time.Time `json:"valid_until"`
	Records  []Record  `json:"records"`
	digest   string
}

// Translation describes operator-approved synthesized address spaces.
type Translation struct {
	NAT64    netip.Prefix
	Pool     netip.Prefix
	Reserved []netip.Addr
}

// LocalName checks absolute .local names and preserves DNS label boundaries.
func LocalName(name string) bool {
	if !dns.IsFqdn(name) || len(name) > 1024 {
		return false
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return false
	}
	return dns.IsSubDomain("local.", name)
}

// NameKey gives a case-insensitive canonical DNS name.
func NameKey(name string) string {
	buffer := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buffer, 0, nil, false)
	if err != nil {
		return ""
	}
	for index := 0; index < n && buffer[index] != 0; {
		length := int(buffer[index])
		index++
		for end := index + length; index < end; index++ {
			if buffer[index] >= 'A' && buffer[index] <= 'Z' {
				buffer[index] += 'a' - 'A'
			}
		}
	}
	canonical, _, err := dns.UnpackDomainName(buffer[:n], 0)
	if err != nil {
		return ""
	}
	return canonical
}

// Decode validates a complete candidate before any live state changes.
func Decode(data []byte, now time.Time, source *policy.SourcePolicy, translation *Translation) (Snapshot, error) {
	var s Snapshot
	if err := jsonwire.Decode(data, MaxBytes, &s); err != nil {
		return s, err
	}
	if source == nil || (s.Schema != 1 && (s.Schema != 2 || translation == nil)) || s.Epoch == "" || len(s.Epoch) > 128 || s.Revision < 1 || s.Records == nil || len(s.Records) > MaxRecords || s.Issued.IsZero() || s.Until.IsZero() || !s.Until.After(s.Issued) || s.Until.Sub(s.Issued) > Lease || s.Issued.Sub(now) > ClockSkew || !s.Until.After(now) {
		return s, errors.New("invalid catalog header or lease")
	}
	sources := source.Sources()
	ids := make(map[string]bool)
	for index := range s.Records {
		r := &s.Records[index]
		if r.Type != "A" && r.Type != "AAAA" && r.Type != "PTR" && r.Type != "SRV" && r.Type != "TXT" {
			return s, errors.New("unsupported catalog type")
		}
		if r.ID == "" || len(r.ID) > 128 || ids[r.ID] || !LocalName(r.Name) || r.Source == "" || len(r.Source) > 128 || len(sources[r.Source]) == 0 || r.Data == "" || len(r.Data) > 4096 || r.Expires.IsZero() || len(r.NativeID) > 128 || (r.NativeID != "" && s.Schema != 2) {
			return s, errors.New("invalid catalog record")
		}
		ids[r.ID] = true
		rr, err := r.RR(MaxTTL)
		if err != nil {
			return s, fmt.Errorf("invalid DNS record: %w", err)
		}
		switch value := rr.(type) {
		case *dns.A:
			if r.NativeID == "" {
				err = source.CheckAddress(r.Source, netip.MustParseAddr(value.A.String()))
			}
		case *dns.AAAA:
			if r.NativeID == "" {
				err = source.CheckAddress(r.Source, netip.MustParseAddr(value.AAAA.String()))
			}
		case *dns.PTR:
			if !LocalName(value.Ptr) {
				err = errors.New("PTR target outside local")
			}
		case *dns.SRV:
			if !LocalName(value.Target) {
				err = errors.New("SRV target outside local")
			}
		case *dns.TXT:
		default:
			err = errors.New("unsupported catalog type")
		}
		if err != nil {
			return s, err
		}
	}
	if s.Schema == 2 {
		if err := validateDerived(s, now, *translation); err != nil {
			return s, err
		}
	}
	slices.SortFunc(s.Records, func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
	encoded, err := json.Marshal(s.Records)
	if err != nil {
		return s, err
	}
	sum := sha256.Sum256(encoded)
	s.digest = hex.EncodeToString(sum[:])
	return s, nil
}

// Catalog retains accepted watermarks even after its lease expires.
type Catalog struct {
	mu           sync.Mutex
	policy       *policy.SourcePolicy
	translation  *Translation
	snapshot     *Snapshot
	anchor       Moment
	last         time.Duration
	feedDeadline time.Duration
	deadlines    map[string]time.Duration
	failed       bool
}

// New makes an empty catalog. Translation admission is optional and explicit.
func New(source *policy.SourcePolicy, translation *Translation) *Catalog {
	return &Catalog{policy: source, translation: translation}
}

func (c *Catalog) checkClock(now Moment) error {
	if c.failed || now.Wall.IsZero() || now.Mono < c.last {
		c.failed = true
		return errors.New("clock discontinuity requires a fresh bootstrap")
	}
	if c.snapshot != nil {
		difference := now.Wall.Sub(c.anchor.Wall) - (now.Mono - c.anchor.Mono)
		if difference > ClockSkew || difference < -ClockSkew {
			c.failed = true
			return errors.New("clock discontinuity")
		}
	}
	c.last = now.Mono
	return nil
}

// Install atomically replaces records; identical replay never extends validity.
func (c *Catalog) Install(data []byte, now Moment) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkClock(now); err != nil {
		return false, err
	}
	s, err := Decode(data, now.Wall, c.policy, c.translation)
	if err != nil {
		return false, err
	}
	old := c.snapshot
	if old != nil {
		if s.Epoch != old.Epoch || s.Revision < old.Revision || s.Issued.Before(old.Issued) || (s.Revision == old.Revision && s.digest != old.digest) {
			return false, errors.New("catalog watermark rollback or mutation")
		}
		if s.Revision == old.Revision && s.Issued.Equal(old.Issued) {
			if !s.Until.Equal(old.Until) {
				return false, errors.New("replay cannot extend a lease")
			}
			return false, nil
		}
	}
	previous := make(map[string]Record)
	if old != nil {
		for _, r := range old.Records {
			previous[r.ID] = r
		}
	}
	deadlines := make(map[string]time.Duration)
	for _, r := range s.Records {
		deadline := now.Mono + r.Expires.Sub(now.Wall)
		if p, ok := previous[r.ID]; ok && p.Expires.Equal(r.Expires) {
			deadline = min(deadline, c.deadlines[r.ID])
		}
		deadlines[r.ID] = deadline
	}
	c.snapshot, c.anchor = &s, now
	c.deadlines, c.feedDeadline = deadlines, now.Mono+min(Lease, s.Until.Sub(now.Wall))
	return true, nil
}

// TimedRecord contains the remaining floored validity of one catalog record.
type TimedRecord struct {
	Record Record
	TTL    uint32
}

// Records returns only independently fresh records, withholding clock failures.
func (c *Catalog) Records(now Moment) []TimedRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checkClock(now) != nil || c.snapshot == nil {
		return nil
	}
	result := make([]TimedRecord, 0, len(c.snapshot.Records))
	for _, r := range c.snapshot.Records {
		remaining := min(Lease, c.feedDeadline-now.Mono, c.deadlines[r.ID]-now.Mono, r.Expires.Sub(now.Wall), c.snapshot.Until.Sub(now.Wall))
		if r.NativeID != "" {
			remaining = min(remaining, c.deadlines[r.NativeID]-now.Mono)
		}
		if remaining >= time.Second {
			result = append(result, TimedRecord{r, uint32(remaining / time.Second)})
		}
	}
	return result
}

// ClockFailed reports whether a fresh gateway bootstrap is required.
func (c *Catalog) ClockFailed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.failed }

func validateDerived(s Snapshot, now time.Time, t Translation) error {
	byID := make(map[string]Record)
	native := make(map[string]bool)
	for _, r := range s.Records {
		byID[r.ID] = r
		if r.NativeID == "" && r.Expires.After(now) {
			native[r.Source+"\x00"+NameKey(r.Name)+"\x00"+r.Type] = true
		}
	}
	seen, aliases := make(map[string]bool), make(map[netip.Addr]netip.Addr)
	for _, r := range s.Records {
		if r.NativeID == "" {
			continue
		}
		n, ok := byID[r.NativeID]
		key := r.NativeID + "\x00" + r.Type
		if !ok || n.NativeID != "" || n.Source != r.Source || NameKey(n.Name) != NameKey(r.Name) || r.Expires.After(n.Expires) || r.Expires.After(s.Until) || seen[key] || native[r.Source+"\x00"+NameKey(r.Name)+"\x00"+r.Type] {
			return errors.New("invalid translated provenance or lease")
		}
		seen[key] = true
		address, err := netip.ParseAddr(r.Data)
		if err != nil {
			return err
		}
		target, err := netip.ParseAddr(n.Data)
		if err != nil {
			return err
		}
		switch {
		case r.Type == "AAAA" && n.Type == "A":
			translated, err := policy.NAT64(t.NAT64, target)
			if err != nil || translated != address || t.Pool.Contains(target) {
				return errors.New("invalid NAT64 derivation")
			}
		case r.Type == "A" && n.Type == "AAAA":
			if !address.Is4() || !t.Pool.Contains(address) || slices.Contains(t.Reserved, address) {
				return errors.New("invalid NAT46 pool alias")
			}
			p, err := policy.New(map[string][]string{"alias": {t.Pool.String()}}, nil)
			if err != nil || p.CheckAddress("alias", address) != nil {
				return errors.New("invalid NAT46 endpoint")
			}
			if prior, ok := aliases[address]; ok && prior != target {
				return errors.New("conflicting NAT46 aliases")
			}
			aliases[address] = target
		default:
			return errors.New("invalid translated record type")
		}
	}
	return nil
}
