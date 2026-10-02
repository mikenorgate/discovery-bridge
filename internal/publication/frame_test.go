package publication

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

func admissionFixture() Admission {
	return Admission{Boot: "test-boot", Links: map[int]observation.Link{
		2: {Source: "lan-a", Generation: "link-a", Families: []int{4, 6}},
		3: {Source: "lan-b", Generation: "link-b", Families: []int{4}},
	}, Owns: func(name string) (bool, error) { return strings.Contains(strings.ToLower(name), "alias"), nil },
		OwnsHost: func(source, name string) (bool, error) { return source == "lan-a" && name == "sensor.local.", nil }}
}

func publicationAnswers(t *testing.T) []catalog.Answer {
	t.Helper()
	var values []catalog.Answer
	for _, text := range []string{
		catalog.Enumeration + " 20 IN PTR _example._tcp.local.",
		"_example._tcp.local. 20 IN PTR Alias._example._tcp.local.",
		"Alias._example._tcp.local. 20 IN SRV 0 0 1234 host-alias.local.",
		`Alias._example._tcp.local. 20 IN TXT "binary=\000\255" ""`,
		"host-alias.local. 20 IN A 192.0.2.42", "host-alias.local. 20 IN AAAA 2001:db8:1::42",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, catalog.Answer{RR: rr, Source: "lan-a", Unique: rr.Header().Rrtype != dns.TypePTR})
	}
	return values
}

func TestCompletePublicationFrameUsesIndependentLeaseAndCacheTTL(t *testing.T) {
	a := admissionFixture()
	answers := publicationAnswers(t)
	payload, err := Frame(a.Boot, 1, 0, []avahi.Intent{{Interface: 2, Family: 4, Deadline: 20 * time.Second, Records: answers}})
	if err != nil {
		t.Fatal(err)
	}
	sequence, intents, err := a.Decode(payload, 500*time.Millisecond, 0)
	if err != nil || sequence != 1 || len(intents) != 1 || len(intents[0].Records) != 6 || intents[0].Deadline != 20*time.Second {
		t.Fatal(sequence, intents, err)
	}
	for _, answer := range intents[0].Records {
		if answer.RR.Header().Ttl != 1 {
			t.Fatal("publisher cache TTL exceeded one second")
		}
	}
	a.Owns = func(string) (bool, error) { return false, nil }
	if _, _, err := a.Decode(payload, 500*time.Millisecond, 0); err == nil {
		t.Fatal("unreserved aliases accepted")
	}
}

func TestPublicationRejectsReplayPartialAndAmbiguousSnapshots(t *testing.T) {
	a := admissionFixture()
	payload, err := Frame(a.Boot, 1, 0, []avahi.Intent{{Interface: 2, Family: 4, Deadline: 20 * time.Second, Records: publicationAnswers(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Decode(payload, 500*time.Millisecond, 1); err == nil {
		t.Fatal("replayed frame accepted")
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["boot"] = "another-boot" },
		func(v map[string]any) { v["sequence"] = 0 },
		func(v map[string]any) { v["sequence"] = nil },
		func(v map[string]any) { v["issued"] = -1 },
		func(v map[string]any) { v["issued"] = 1 },
		func(v map[string]any) { v["groups"] = nil },
		func(v map[string]any) { groupOf(v)["deadline"] = 31 },
		func(v map[string]any) { groupOf(v)["deadline"] = .4 },
		func(v map[string]any) { groupOf(v)["family"] = 5 },
		func(v map[string]any) { groupOf(v)["interface"] = 99 },
		func(v map[string]any) { groupOf(v)["records"] = nil },
		func(v map[string]any) { records := groupOf(v)["records"].([]any); groupOf(v)["records"] = records[:4] },
		func(v map[string]any) { v["groups"] = append(v["groups"].([]any), groupOf(v)) },
		func(v map[string]any) { r := groupOf(v)["records"].([]any); groupOf(v)["records"] = append(r, r[4]) },
		func(v map[string]any) { groupOf(v)["records"].([]any)[4].(map[string]any)["source"] = "foreign" },
		func(v map[string]any) { groupOf(v)["records"].([]any)[0].(map[string]any)["unique"] = true },
		func(v map[string]any) { groupOf(v)["records"].([]any)[4].(map[string]any)["unique"] = false },
		func(v map[string]any) { groupOf(v)["records"].([]any)[4].(map[string]any)["unique"] = nil },
		func(v map[string]any) {
			groupOf(v)["records"].([]any)[4].(map[string]any)["data"] = "192.0.2.42\nother.local. IN A 192.0.2.43"
		},
		func(v map[string]any) {
			groupOf(v)["records"].([]any)[0].(map[string]any)["data"] = "_foreign._tcp.example.org."
		},
	} {
		var value map[string]any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		bad, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, intents, err := a.Decode(bad, 500*time.Millisecond, 0); err == nil || len(intents) != 0 {
			t.Fatal("invalid frame partially installed", string(bad), err)
		}
	}
	duplicate := strings.Replace(string(payload), `"sequence":1`, `"sequence":1,"sequence":2`, 1)
	if _, _, err := a.Decode([]byte(duplicate), 500*time.Millisecond, 0); err == nil {
		t.Fatal("duplicate JSON field accepted")
	}
}

func groupOf(v map[string]any) map[string]any { return v["groups"].([]any)[0].(map[string]any) }

func TestOriginalHostnameMayPublishOnlyOnAnotherLink(t *testing.T) {
	a := admissionFixture()
	rr, err := dns.NewRR("sensor.local. 20 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{2, 3} {
		payload, err := Frame(a.Boot, 1, 0, []avahi.Intent{{Interface: index, Family: 4, Deadline: 20 * time.Second, Records: []catalog.Answer{{RR: rr, Source: "lan-a", Unique: true}}}})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = a.Decode(payload, 500*time.Millisecond, 0)
		if (index == 2) != (err != nil) {
			t.Fatal("original hostname scope changed", index, err)
		}
	}
}
