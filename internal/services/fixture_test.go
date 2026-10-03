//go:build linux

package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/tests/fixtures"
)

func TestServiceProducerAndReceiverWireFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := settings()
	s.VIPNetworks = []string{"2001:db8:1000:ff00::/60"} // Documentation address pool.
	s.Services[0].Instance = "Web café . test"
	s.Services[0].TXT = map[string]string{"path": "/", "title": "Web café", "escaped": "quote\" slash\\"}
	scope, err := policy.New(map[string][]string{"kubernetes": s.VIPNetworks}, nil)
	if err != nil {
		t.Fatal(err)
	}
	serviceData := strings.ReplaceAll(serviceJSON, "2001:db8:ff00::22", "2001:db8:1000:ff00::22")
	sliceData := []byte(`{"kind":"EndpointSliceList","apiVersion":"discovery.k8s.io/v1","items":[` + sliceJSON + `]}`)
	read := func(_ context.Context, argv []string) (json.RawMessage, error) {
		if slices.Contains(argv, "config") {
			return []byte(`{"clusters":[{"cluster":{"server":"https://fixture"}}]}`), nil
		}
		if strings.Contains(argv[len(argv)-1], "endpointslices?") {
			return sliceData, nil
		}
		return []byte(serviceData), nil
	}
	producer, err := NewProducer(s, read)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := producer.Snapshot(ctx)
	if err != nil || len(snapshot.Services) != 1 {
		t.Fatal(snapshot, err)
	}
	output, err := fixtures.Files.ReadFile("services.json")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted int      `json:"accepted"`
		Received [][]any  `json:"received"`
		Snapshot Snapshot `json:"snapshot"`
		Produced [][]any  `json:"produced"`
	}
	if err := json.Unmarshal(output, &result); err != nil || result.Accepted != 200 {
		t.Fatal(string(output), err)
	}
	if !reflect.DeepEqual(result.Snapshot.Services, snapshot.Services) {
		t.Fatal("Selected external Service intents differ from fixture", snapshot.Services, result.Snapshot.Services)
	}
	data, err := json.Marshal(result.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewReceiver("kubernetes", scope)
	if err != nil {
		t.Fatal(err)
	}
	now := catalog.Moment{Wall: result.Snapshot.Issued, Mono: time.Hour}
	if err := receiver.Install(data, now); err != nil {
		t.Fatal("Receiver rejected fixture Service intent", err)
	}
	var signatures [][]any
	for _, record := range receiver.Records(now) {
		rr, err := record.RR(1)
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 4096)
		n, err := dns.PackRR(rr, wire, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		_, nameEnd, err := dns.UnpackDomainName(wire[:n], 0)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, []any{hex.EncodeToString(wire[:nameEnd]), float64(rr.Header().Rrtype), hex.EncodeToString(wire[nameEnd+10 : n]), record.Source})
	}
	less := func(a, b []any) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right)
	}
	for _, values := range [][][]any{signatures, result.Produced, result.Received} {
		slices.SortFunc(values, less)
	}
	if !reflect.DeepEqual(signatures, result.Received) || !reflect.DeepEqual(signatures, result.Produced) {
		t.Fatal("Service DNS name or RDATA wire differs from fixture", signatures, result.Received, result.Produced)
	}
	if records := receiver.Records(catalog.Moment{Wall: now.Wall.Add(15 * time.Second), Mono: now.Mono + 15*time.Second}); len(records) != 0 {
		t.Fatal("expired Service intent survived", records)
	}
}
