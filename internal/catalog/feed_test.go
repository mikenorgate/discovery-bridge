package catalog

import (
	"encoding/json"
	"testing"
	"time"
)

func feedPayload(t *testing.T, f *NodeFeed, s Snapshot, generation, policyRevision int64, unique []any) []byte {
	t.Helper()
	nonce, err := f.BeginRequest()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"schema": 1, "generation": generation, "policy_revision": policyRevision, "nonce": nonce, "snapshot": s, "unique_rrsets": unique})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFeedNonceWatermarksAndWithdrawal(t *testing.T) {
	now := Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Hour}
	s := Snapshot{Schema: 1, Epoch: "test", Revision: 1, Issued: now.Wall, Until: now.Wall.Add(Lease), Records: []Record{{ID: "a", Name: "sensor.local.", Type: "A", Data: "192.0.2.42", Source: "lab-a", Expires: now.Wall.Add(20 * time.Second)}}}
	f := NewNodeFeed(sourcePolicy(t), nil)
	unique := []any{[]any{"sensor.local.", 1}}
	payload := feedPayload(t, f, s, 1, 1, unique)
	if _, err := f.Accept(payload, now); err != nil {
		t.Fatal(err)
	}
	if view := f.View(now); len(view) != 1 || !view[0].Unique {
		t.Fatal(view)
	}
	if _, err := f.Accept(payload, now); err == nil {
		t.Fatal("accepted unsolicited replay")
	}
	if _, err := f.BeginRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Accept(payload, now); err == nil {
		t.Fatal("accepted previous request nonce")
	}
	if len(f.View(now)) != 1 {
		t.Fatal("bad nonce changed authority")
	}
	if _, err := f.Accept(feedPayload(t, f, s, 1, 1, []any{}), now); err == nil {
		t.Fatal("ownership mutation accepted without revision")
	}
	s.Revision++
	s.Records = []Record{}
	if _, err := f.Accept(feedPayload(t, f, s, 1, 1, []any{}), now); err != nil {
		t.Fatal(err)
	}
	if len(f.View(now)) != 0 {
		t.Fatal("full replacement failed to withdraw")
	}
	s.Epoch = "new-boot"
	s.Revision = 1
	if _, err := f.Accept(feedPayload(t, f, s, 1, 1, []any{}), now); err == nil {
		t.Fatal("epoch changed without generation")
	}
	if _, err := f.Accept(feedPayload(t, f, s, 2, 1, []any{}), now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Accept(feedPayload(t, f, s, 1, 1, []any{}), now); err == nil {
		t.Fatal("generation rollback accepted")
	}
}

func TestFeedRejectsUnknownOwnershipAtomically(t *testing.T) {
	now := Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Hour}
	s := Snapshot{Schema: 1, Epoch: "test", Revision: 1, Issued: now.Wall, Until: now.Wall.Add(Lease), Records: []Record{{ID: "a", Name: "sensor.local.", Type: "A", Data: "192.0.2.42", Source: "lab-a", Expires: now.Wall.Add(20 * time.Second)}}}
	f := NewNodeFeed(sourcePolicy(t), nil)
	for _, unique := range [][]any{
		{[]any{"absent.local.", 1}},
		{[]any{"sensor.local.", 1}, []any{"sensor.local.", 1}},
		{[]any{"sensor.local.", 12}},
		{[]any{"sensor.local.", true}},
	} {
		if _, err := f.Accept(feedPayload(t, f, s, 1, 1, unique), now); err == nil {
			t.Fatal("accepted invalid ownership", unique)
		}
	}
	if len(f.View(now)) != 0 {
		t.Fatal("invalid ownership installed records")
	}
}
