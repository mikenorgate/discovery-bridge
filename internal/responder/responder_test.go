package responder

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

func hostView(t *testing.T) []catalog.Answer {
	t.Helper()
	var result []catalog.Answer
	for _, text := range []string{"sensor.local. 20 IN A 192.0.2.42", "sensor.local. 20 IN A 192.0.2.43", "sensor.local. 20 IN AAAA 2001:db8:1::42"} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, catalog.Answer{RR: rr, Source: "lab-a", Unique: true})
	}
	return result
}

func queryWire(t *testing.T, name string, kind uint16, qu bool, known []dns.RR) []byte {
	t.Helper()
	class := uint16(dns.ClassINET)
	if qu {
		class |= 0x8000
	}
	m := dns.Msg{MsgHdr: dns.MsgHdr{Id: 123, RecursionDesired: true}, Question: []dns.Question{{Name: name, Qtype: kind, Qclass: class}}, Answer: known}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestQuestionOnlyLookupAndPacketAdmission(t *testing.T) {
	known := hostView(t)[0].RR
	wire := queryWire(t, "sensor.local.", dns.TypeA, true, []dns.RR{known})
	query, err := Parse(wire, false)
	if err != nil {
		t.Fatal(err)
	}
	value, err := query.Lookup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"schema":1,"questions":[{"name":"sensor.local.","type":1,"class":1}]}`
	if string(data) != expected {
		t.Fatal(string(data))
	}
	for _, bad := range [][]byte{append(append([]byte{}, wire...), 0), queryWire(t, "sensor.example.", dns.TypeA, false, nil), queryWire(t, "sensor.local.", dns.TypeAXFR, false, nil)} {
		if _, err := Parse(bad, false); err == nil {
			t.Fatal("accepted invalid query")
		}
	}
	wire[2] |= 0x80
	if _, err := Parse(wire, false); err == nil {
		t.Fatal("response became a lookup")
	}
}

func TestKnownAnswerRRSetAndLegacyReplies(t *testing.T) {
	view := hostView(t)
	query, err := Parse(queryWire(t, "sensor.local.", dns.TypeA, false, []dns.RR{view[0].RR}), false)
	if err != nil {
		t.Fatal(err)
	}
	r := New()
	result, err := r.Build(query, view, time.Hour, 5353, 6, 1232, false)
	if err != nil || len(result.Replies) != 1 {
		t.Fatal(result, err)
	}
	message, err := Message(result.Replies[0].Wire)
	if err != nil || len(message.Answer) != 2 || !message.Response || len(message.Question) != 0 || message.Id != 0 {
		t.Fatal(message, err)
	}
	for _, rr := range message.Answer {
		if rr.Header().Class != 0x8001 {
			t.Fatal("unique RRset lost cache-flush ownership")
		}
	}
	query.Known = []dns.RR{view[0].RR, view[1].RR}
	result, err = r.Build(query, view, time.Hour, 5353, 6, 1232, false)
	if err != nil || len(result.Replies) != 0 {
		t.Fatal("known answer suppression failed", result, err)
	}
	result, err = r.Build(query, view, time.Hour, 12345, 6, 1232, false)
	if err != nil || len(result.Replies) != 1 || !result.Replies[0].Peer {
		t.Fatal(result, err)
	}
	message, err = Message(result.Replies[0].Wire)
	if err != nil || message.Id != 123 || !message.RecursionDesired || len(message.Question) != 1 {
		t.Fatal(message, err)
	}
	for _, rr := range message.Answer {
		if rr.Header().Class != 1 || rr.Header().Ttl != 10 {
			t.Fatal("legacy TTL or cache flush", rr)
		}
	}
}

func TestSuccessfulHistoryQUAndGoodbyes(t *testing.T) {
	view := hostView(t)
	query, err := Parse(queryWire(t, "sensor.local.", dns.TypeA, true, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	r := New()
	result, err := r.Build(query, view, time.Hour, 5353, 6, 1232, false)
	if err != nil || len(result.Replies) != 1 || result.Replies[0].Peer {
		t.Fatal("first QU requires multicast", result, err)
	}
	// Plans have no effect until the socket adapter confirms a successful send.
	again, err := r.Build(query, view, time.Hour, 5353, 6, 1232, false)
	if err != nil || !reflect.DeepEqual(result, again) {
		t.Fatal("unsent plan altered history")
	}
	r.NoteSent(result.Replies[0], time.Hour)
	result, err = r.Build(query, view, time.Hour+2*time.Second, 5353, 6, 1232, false)
	if err != nil || len(result.Replies) != 1 || !result.Replies[0].Peer {
		t.Fatal("recent QU requires unicast", result, err)
	}
	withdrawals, err := r.Withdrawals(nil, 6)
	if err != nil || len(withdrawals) != 1 {
		t.Fatal(withdrawals, err)
	}
	m, err := Message(withdrawals[0].Wire)
	if err != nil || !m.Response || len(m.Question) != 0 || len(m.Answer) != 2 {
		t.Fatal(m, err)
	}
	for _, rr := range m.Answer {
		if rr.Header().Ttl != 0 || rr.Header().Class != 1 {
			t.Fatal("invalid goodbye", rr)
		}
	}
	r.NoteSent(withdrawals[0], time.Hour+3*time.Second)
	withdrawals, err = r.Withdrawals(nil, 6)
	if err != nil || len(withdrawals) != 0 {
		t.Fatal("successful goodbye retained history")
	}
}

func TestUniqueRRSetNeverSplit(t *testing.T) {
	query, err := Parse(queryWire(t, "sensor.local.", dns.TypeA, false, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	view := hostView(t)
	for index := 44; index < 75; index++ {
		rr := dns.Copy(view[0].RR).(*dns.A)
		rr.A = rr.A.To4()
		rr.A[3] = byte(index)
		view = append(view, catalog.Answer{RR: rr, Source: "lab-a", Unique: true})
	}
	result, err := New().Build(query, view, time.Hour, 5353, 6, 512, false)
	if err != nil || !result.Oversized || len(result.Replies) != 0 {
		t.Fatal("oversized unique RRset split", result, err)
	}
}
