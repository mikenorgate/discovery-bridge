package catalog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

// MaxFeedBytes bounds the catalog and ownership envelope.
const MaxFeedBytes = 2_097_152

type envelope struct {
	Schema         int               `json:"schema"`
	Generation     int64             `json:"generation"`
	PolicyRevision int64             `json:"policy_revision"`
	Nonce          string            `json:"nonce"`
	Unique         []json.RawMessage `json:"unique_rrsets"`
	Snapshot       json.RawMessage   `json:"snapshot"`
}

type watermark struct {
	generation int64
	policy     int64
	epoch      string
	revision   int64
	signature  [32]byte
	snapshot   Snapshot
}

// NodeFeed owns an in-memory gateway catalog and its request/replay watermarks.
type NodeFeed struct {
	mu          sync.Mutex
	policy      *policy.SourcePolicy
	translation *Translation
	catalog     *Catalog
	authority   Authority
	pending     string
	watermark   *watermark
}

// NewNodeFeed creates a fresh node bootstrap without a disk cache.
func NewNodeFeed(source *policy.SourcePolicy, translation *Translation) *NodeFeed {
	return &NodeFeed{policy: source, translation: translation, catalog: New(source, translation), authority: Authority{}}
}

// BeginRequest creates one live request challenge; only one may be outstanding.
func (f *NodeFeed) BeginRequest() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending != "" {
		return "", errors.New("catalog request already pending")
	}
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	f.pending = hex.EncodeToString(value[:])
	return f.pending, nil
}

// AbortRequest abandons a failed request without renewing any catalog lease.
func (f *NodeFeed) AbortRequest() { f.mu.Lock(); defer f.mu.Unlock(); f.pending = "" }

// Accept validates the whole envelope before replacing authority or catalog.
func (f *NodeFeed) Accept(data []byte, now Moment) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	expected := f.pending
	f.pending = ""
	if expected == "" {
		return 0, errors.New("catalog response has no live challenge")
	}
	var value envelope
	if err := jsonwire.Decode(data, MaxFeedBytes, &value); err != nil {
		return 0, err
	}
	if value.Schema != 1 || value.Nonce != expected || value.Generation < 1 || value.PolicyRevision < 1 || value.Unique == nil || len(value.Unique) > MaxRecords {
		return 0, errors.New("invalid catalog envelope")
	}
	s, err := Decode(value.Snapshot, now.Wall, f.policy, f.translation)
	if err != nil {
		return 0, err
	}
	present := make(map[RRSet]bool)
	for _, r := range s.Records {
		if r.Type != "PTR" {
			present[RRSet{NameKey(r.Name), dns.StringToType[r.Type]}] = true
		}
	}
	unique := make(map[RRSet]bool)
	var keys []string
	for _, raw := range value.Unique {
		var pair []json.RawMessage
		if err := jsonwire.Decode(raw, 2048, &pair); err != nil || len(pair) != 2 {
			return 0, errors.New("invalid unique RRset pair")
		}
		var name string
		var kind uint16
		if err := jsonwire.Decode(pair[0], 1100, &name); err != nil {
			return 0, err
		}
		if err := jsonwire.Decode(pair[1], 8, &kind); err != nil {
			return 0, err
		}
		key := RRSet{NameKey(name), kind}
		if !LocalName(name) || !present[key] || unique[key] {
			return 0, errors.New("unknown or duplicate ownership claim")
		}
		unique[key] = true
		keys = append(keys, fmt.Sprintf("%s:%d", key.Name, key.Type))
	}
	slices.Sort(keys)
	encoded, err := json.Marshal([]any{s.digest, keys, value.PolicyRevision})
	if err != nil {
		return 0, err
	}
	signature := sha256.Sum256(encoded)
	old := f.watermark
	if old != nil {
		if value.Generation < old.generation || value.PolicyRevision < old.policy {
			return 0, errors.New("generation or policy rollback")
		}
		if value.Generation == old.generation {
			if s.Epoch != old.epoch || s.Revision < old.revision || s.Issued.Before(old.snapshot.Issued) || (s.Revision == old.revision && signature != old.signature) || (s.Issued.Equal(old.snapshot.Issued) && !s.Until.Equal(old.snapshot.Until)) {
				return 0, errors.New("catalog replay or mutation")
			}
		}
	}
	candidate := New(f.policy, f.translation)
	if old != nil && old.generation == value.Generation && !f.catalog.ClockFailed() {
		candidate = f.catalog.clone()
	}
	if _, err := candidate.Install(value.Snapshot, now); err != nil {
		if candidate.ClockFailed() {
			f.catalog.mu.Lock()
			f.catalog.failed = true
			f.catalog.mu.Unlock()
		}
		return 0, err
	}
	authority := Authority{IDs: make(map[string]bool), Unique: unique}
	for _, r := range s.Records {
		authority.IDs[r.ID] = true
	}
	f.catalog, f.authority = candidate, authority
	f.watermark = &watermark{generation: value.Generation, policy: value.PolicyRevision, epoch: s.Epoch, revision: s.Revision, signature: signature, snapshot: s}
	return s.Revision, nil
}

func (c *Catalog) clone() *Catalog {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := New(c.policy, c.translation)
	n.snapshot, n.anchor, n.last, n.feedDeadline, n.failed = c.snapshot, c.anchor, c.last, c.feedDeadline, c.failed
	n.deadlines = make(map[string]time.Duration)
	for key, value := range c.deadlines {
		n.deadlines[key] = value
	}
	return n
}

// View constructs fresh coherent records under the accepted gateway authority.
func (f *NodeFeed) View(now Moment) []Answer {
	return f.ViewBlocked(now, nil)
}

// ViewBlocked additionally withholds locally claimed names and their dependencies.
func (f *NodeFeed) ViewBlocked(now Moment, blocked map[string]bool) []Answer {
	f.mu.Lock()
	defer f.mu.Unlock()
	authority := f.authority
	authority.Blocked = blocked
	return ResponseView(f.catalog.Records(now), authority)
}

// ValidNonce recognizes a bounded lowercase hexadecimal request challenge.
func ValidNonce(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
