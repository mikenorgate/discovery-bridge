package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

// Feed owns one gateway generation and exposes leased full catalogs.
type Feed struct {
	mu             sync.Mutex
	policy         *policy.SourcePolicy
	source         *catalog.Catalog
	authority      catalog.Authority
	generation     *state.Generation
	epoch          string
	sourceRevision int64
	revision       int64
	signature      [32]byte
	closed         bool
	// Render samples already-established translator readiness; it never allocates.
	Render func([]catalog.Record, catalog.Moment) []catalog.Record
}

// NewFeed acquires the exclusive persistent gateway generation.
func NewFeed(ctx context.Context, source *policy.SourcePolicy, path string) (*Feed, error) {
	if source == nil {
		return nil, errors.New("explicit source policy required")
	}
	g, err := state.OpenGeneration(ctx, path)
	if err != nil {
		return nil, err
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, errors.Join(err, g.Close())
	}
	return &Feed{policy: source, source: catalog.New(source, nil), generation: g, epoch: hex.EncodeToString(epoch[:]), authority: catalog.Authority{}}, nil
}

// Export preserves stable Python record hashes and the sampled absolute expiry.
func Export(answers []catalog.Answer, observed time.Time) ([]catalog.Record, []catalog.RRSet, error) {
	records := make([]catalog.Record, 0, len(answers))
	sets := make(map[catalog.RRSet]bool)
	for _, a := range answers {
		header := a.RR.Header()
		data := strings.TrimPrefix(a.RR.String(), header.String())
		encoded, err := jsonwire.Encode([]any{a.Source, header.Name, header.Rrtype, data})
		if err != nil {
			return nil, nil, err
		}
		hash := sha256.Sum256(encoded)
		records = append(records, catalog.Record{ID: hex.EncodeToString(hash[:]), Name: header.Name, Type: dnsType(header.Rrtype), Data: data, Source: a.Source, Expires: observed.Add(time.Duration(header.Ttl) * time.Second)})
		if a.Unique {
			sets[a.Set()] = true
		}
	}
	slices.SortFunc(records, func(a, b catalog.Record) int { return strings.Compare(a.ID, b.ID) })
	unique := make([]catalog.RRSet, 0, len(sets))
	for set := range sets {
		unique = append(unique, set)
	}
	slices.SortFunc(unique, func(a, b catalog.RRSet) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return int(a.Type) - int(b.Type)
	})
	return records, unique, nil
}

func dnsType(kind uint16) string {
	switch kind {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 12:
		return "PTR"
	case 33:
		return "SRV"
	case 16:
		return "TXT"
	default:
		return ""
	}
}

// Publish replaces source observations with their already-sampled expiries.
func (f *Feed) Publish(answers []catalog.Answer, observed time.Time, now catalog.Moment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("gateway owner closed")
	}
	records, sets, err := Export(answers, observed)
	if err != nil {
		return err
	}
	f.sourceRevision++
	s := catalog.Snapshot{Schema: 1, Epoch: f.epoch, Revision: f.sourceRevision, Issued: now.Wall, Until: now.Wall.Add(catalog.Lease), Records: records}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := f.source.Install(data, now); err != nil {
		return err
	}
	authority := catalog.Authority{IDs: make(map[string]bool), Unique: make(map[catalog.RRSet]bool)}
	for _, r := range records {
		authority.IDs[r.ID] = true
	}
	for _, set := range sets {
		authority.Unique[set] = true
	}
	f.authority = authority
	return nil
}

// Withdraw removes source state without losing gateway replay watermarks.
func (f *Feed) Withdraw() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source = catalog.New(f.policy, nil)
	f.authority = catalog.Authority{}
}

// Read returns one bounded envelope correlated with the caller's challenge.
func (f *Feed) Read(nonce string, now catalog.Moment) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || !catalog.ValidNonce(nonce) {
		return nil, errors.New("invalid catalog read")
	}
	answers := catalog.ResponseView(f.source.Records(now), f.authority)
	records, unique, err := Export(answers, now.Wall)
	if err != nil {
		return nil, err
	}
	schema := 1
	if f.Render != nil {
		byID := make(map[string]catalog.Record)
		for _, r := range records {
			byID[r.ID] = r
		}
		originalSets := make(map[catalog.RRSet]bool)
		for _, set := range unique {
			originalSets[set] = true
		}
		rendered := f.Render(records, now)
		for _, r := range rendered {
			if r.NativeID == "" {
				continue
			}
			native, ok := byID[r.NativeID]
			if !ok {
				return nil, errors.New("renderer returned an unknown native record")
			}
			records = append(records, r)
			schema = 2
			if originalSets[catalog.RRSet{Name: catalog.NameKey(native.Name), Type: kindType(native.Type)}] {
				unique = append(unique, catalog.RRSet{Name: catalog.NameKey(r.Name), Type: kindType(r.Type)})
			}
		}
	}
	claims := make([][]any, 0, len(unique))
	for _, set := range unique {
		claims = append(claims, []any{set.Name, set.Type})
	}
	signatureData, err := jsonwire.Encode([]any{records, claims, 1})
	if err != nil {
		return nil, err
	}
	signature := sha256.Sum256(signatureData)
	revision := f.revision
	if signature != f.signature {
		revision++
	}
	snapshot := catalog.Snapshot{Schema: schema, Epoch: f.epoch, Revision: revision, Issued: now.Wall, Until: now.Wall.Add(catalog.Lease), Records: records}
	snapshotData, err := json.Marshal(snapshot)
	if err != nil || len(snapshotData) > catalog.MaxBytes {
		return nil, errors.New("snapshot export limit")
	}
	result, err := json.Marshal(struct {
		Schema         int              `json:"schema"`
		Generation     int64            `json:"generation"`
		PolicyRevision int              `json:"policy_revision"`
		Nonce          string           `json:"nonce"`
		Unique         [][]any          `json:"unique_rrsets"`
		Snapshot       catalog.Snapshot `json:"snapshot"`
	}{1, f.generation.Number, 1, nonce, claims, snapshot})
	if err != nil || len(result) > catalog.MaxFeedBytes {
		return nil, errors.New("catalog envelope export limit")
	}
	f.revision, f.signature = revision, signature
	return result, nil
}

func kindType(kind string) uint16 {
	switch kind {
	case "A":
		return 1
	case "AAAA":
		return 28
	case "PTR":
		return 12
	case "SRV":
		return 33
	case "TXT":
		return 16
	default:
		return 0
	}
}

// Close releases only gateway state, never source or publisher ownership.
func (f *Feed) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.generation.Close()
}
