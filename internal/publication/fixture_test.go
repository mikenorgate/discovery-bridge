package publication

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func TestPublicationFrameFixtureAndSQLiteOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "identities.sqlite")
	identities, err := state.Open(ctx, path, "db-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := identities.Close(); err != nil {
			t.Error(err)
		}
	}()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []catalog.Record
	for index, answer := range publicationAnswers(t) {
		rr := answer.RR
		records = append(records, catalog.Record{ID: string(rune('a' + index)), Name: rr.Header().Name, Type: dns.TypeToString[rr.Header().Rrtype], Data: strings.TrimPrefix(rr.String(), rr.Header().String()), Source: answer.Source, Expires: now.Add(20 * time.Second)})
	}
	answers, err := identities.Compile(ctx, records, now)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile("../../tests/fixtures/publication.json")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Sequence int64   `json:"sequence"`
		Records  [][]any `json:"records"`
		Frame    string  `json:"frame"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	payload, err := Frame("fixture-boot", 1, 0, []avahi.Intent{{Interface: 2, Family: 4, Deadline: 20 * time.Second, Records: answers}})
	if err != nil {
		t.Fatal(err)
	}
	var generated, expected any
	if err := json.Unmarshal(payload, &generated); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(result.Frame), &expected); err != nil {
		t.Fatal(err)
	}
	// Record order is immaterial to the complete snapshot contract.
	for _, frame := range []any{generated, expected} {
		for _, group := range frame.(map[string]any)["groups"].([]any) {
			records := group.(map[string]any)["records"].([]any)
			slices.SortFunc(records, func(a, b any) int {
				left, _ := json.Marshal(a)
				right, _ := json.Marshal(b)
				return bytes.Compare(left, right)
			})
		}
	}
	if !reflect.DeepEqual(generated, expected) {
		t.Fatal("generated frame differs from fixture", string(payload), result.Frame)
	}
	a := admissionFixture()
	a.Boot = "fixture-boot"
	a.Owns = func(name string) (bool, error) { return identities.Owns(ctx, name) }
	_, groups, err := a.Decode([]byte(result.Frame), 500*time.Millisecond, 0)
	if err != nil || result.Sequence != 1 || len(groups) != 1 {
		t.Fatal("Admission rejected fixture frame", result.Sequence, err)
	}
	var actual [][]any
	for _, answer := range groups[0].Records {
		key := []byte(answer.Key())
		_, next, err := dns.UnpackDomainName(key, 0)
		if err != nil {
			t.Fatal(err)
		}
		actual = append(actual, []any{hex.EncodeToString(key[:next]), float64(answer.RR.Header().Rrtype), hex.EncodeToString(key[next+10:]), answer.Source, answer.Unique, float64(answer.RR.Header().Ttl)})
	}
	slices.SortFunc(actual, func(a, b []any) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right)
	})
	slices.SortFunc(result.Records, func(a, b []any) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right)
	})
	if !reflect.DeepEqual(actual, result.Records) {
		t.Fatal("Publication wire signatures differ from fixture", actual, result.Records)
	}
}
