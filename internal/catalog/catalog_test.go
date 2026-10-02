package catalog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

type expectedAnswer struct {
	Key    string `json:"key"`
	TTL    uint32 `json:"ttl"`
	Source string `json:"source"`
	Unique bool   `json:"unique"`
}

func sourcePolicy(t *testing.T) *policy.SourcePolicy {
	t.Helper()
	p, err := policy.New(map[string][]string{"lab-a": {"192.0.2.0/24", "2001:db8:1::/64"}, "lab-b": {"198.51.100.0/24", "2001:db8:2::/64"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPythonReferenceViews(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/views.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Case     string           `json:"case"`
		Snapshot json.RawMessage  `json:"snapshot"`
		Expected []expectedAnswer `json:"expected"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	now := Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Hour}
	for _, f := range fixtures {
		t.Run(f.Case, func(t *testing.T) {
			c := New(sourcePolicy(t), nil)
			if _, err := c.Install(f.Snapshot, now); err != nil {
				t.Fatal(err)
			}
			s, err := Decode(f.Snapshot, now.Wall, sourcePolicy(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			authority := Authority{IDs: make(map[string]bool), Unique: make(map[RRSet]bool)}
			for _, r := range s.Records {
				authority.IDs[r.ID] = true
				if r.Type != "PTR" {
					authority.Unique[RRSet{NameKey(r.Name), dns.StringToType[r.Type]}] = true
				}
			}
			view := ResponseView(c.Records(now), authority)
			actual := make([]expectedAnswer, 0, len(view))
			for _, a := range view {
				actual = append(actual, expectedAnswer{hex.EncodeToString([]byte(a.Key())), a.RR.Header().Ttl, a.Source, a.Unique})
			}
			if !reflect.DeepEqual(actual, f.Expected) {
				t.Fatalf("Go view differs from Python\nGo: %#v\nPython: %#v", actual, f.Expected)
			}
		})
	}
}

func snapshotBytes(t *testing.T, s Snapshot) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReplayExpiryAndClockFailure(t *testing.T) {
	now := Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Hour}
	s := Snapshot{Schema: 1, Epoch: "test", Revision: 1, Issued: now.Wall, Until: now.Wall.Add(Lease), Records: []Record{{ID: "a", Name: "sensor.local.", Type: "A", Data: "192.0.2.42", Source: "lab-a", Expires: now.Wall.Add(10 * time.Second)}}}
	c := New(sourcePolicy(t), nil)
	data := snapshotBytes(t, s)
	if changed, err := c.Install(data, now); err != nil || !changed {
		t.Fatal(changed, err)
	}
	advanced := Moment{Wall: now.Wall.Add(5 * time.Second), Mono: now.Mono + 5*time.Second}
	if changed, err := c.Install(data, advanced); err != nil || changed {
		t.Fatal(changed, err)
	}
	if r := c.Records(advanced); len(r) != 1 || r[0].TTL != 5 {
		t.Fatal(r)
	}
	s.Until = s.Until.Add(time.Second)
	if _, err := c.Install(snapshotBytes(t, s), advanced); err == nil {
		t.Fatal("replay renewed lease")
	}
	s.Until = now.Wall.Add(Lease)
	s.Revision = 2
	s.Issued = advanced.Wall
	if _, err := c.Install(snapshotBytes(t, s), advanced); err != nil {
		t.Fatal(err)
	}
	if r := c.Records(Moment{Wall: now.Wall.Add(10 * time.Second), Mono: now.Mono + 10*time.Second}); len(r) != 0 {
		t.Fatal("expired record survived", r)
	}
	if r := c.Records(Moment{Wall: now.Wall.Add(30 * time.Second), Mono: now.Mono + 11*time.Second}); len(r) != 0 || !c.ClockFailed() {
		t.Fatal("wall jump did not fail closed")
	}
}

func TestMalformedSnapshotIsAtomic(t *testing.T) {
	now := Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Mono: time.Hour}
	s := Snapshot{Schema: 1, Epoch: "test", Revision: 1, Issued: now.Wall, Until: now.Wall.Add(Lease), Records: []Record{{ID: "a", Name: "sensor.local.", Type: "A", Data: "192.0.2.42", Source: "lab-a", Expires: now.Wall.Add(10 * time.Second)}}}
	c := New(sourcePolicy(t), nil)
	data := snapshotBytes(t, s)
	if _, err := c.Install(data, now); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(data, []byte("192.0.2.42"), []byte("198.51.100.42"), 1),
		bytes.Replace(data, []byte(`"type":"A"`), []byte(`"type":"CNAME"`), 1),
		append(append([]byte{}, data...), data...),
	} {
		if _, err := c.Install(bad, now); err == nil {
			t.Fatalf("accepted invalid snapshot: %s", bad)
		}
		if len(c.Records(now)) != 1 {
			t.Fatal("invalid replacement changed live records")
		}
	}
}
