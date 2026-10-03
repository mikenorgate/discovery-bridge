package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

const serviceJSON = `{"apiVersion":"v1","kind":"Service","metadata":{"namespace":"services","name":"example","uid":"service-uid","resourceVersion":"10"},"spec":{"type":"LoadBalancer","ports":[{"name":"http","protocol":"TCP","port":80,"targetPort":3000}],"clusterIP":"2001:db8:e000::10"},"status":{"loadBalancer":{"ingress":[{"ip":"2001:db8:ff00::22","ipMode":"VIP"}]}}}`
const sliceJSON = `{"metadata":{"namespace":"services","name":"slice","labels":{"kubernetes.io/service-name":"example"},"ownerReferences":[{"kind":"Service","uid":"service-uid","controller":true}]},"addressType":"IPv6","ports":[{"name":"http","port":3000,"protocol":"TCP"}],"endpoints":[{"addresses":["2001:db8:f004::123"],"conditions":{"ready":true,"serving":true,"terminating":false}}]}`

func selection() config.Service {
	return config.Service{Namespace: "services", Name: "example", Port: "http", Type: "_http._tcp", Instance: "Example web", TXT: map[string]string{"path": "/"}, Subtypes: []string{"test"}}
}
func settings() config.ServicePublisher {
	return config.ServicePublisher{Enabled: true, Kubectl: []string{"/usr/bin/kubectl"}, Kubeconfig: "/etc/kubeconfig", Gateway: config.Endpoint{Host: "2001:db8:1::1", Port: 9444}, VIPNetworks: []string{"2001:db8:ff00::/60"}, Services: []config.Service{selection()}}
}

func scope(t *testing.T, source string) *policy.SourcePolicy {
	t.Helper()
	p, err := policy.New(map[string][]string{source: {"2001:db8:ff00::/60"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func fixture(t *testing.T) (service, []endpointSlice) {
	t.Helper()
	var s service
	var item endpointSlice
	if err := json.Unmarshal([]byte(serviceJSON), &s); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(sliceJSON), &item); err != nil {
		t.Fatal(err)
	}
	return s, []endpointSlice{item}
}

func readyIntent(t *testing.T) Intent {
	t.Helper()
	s, list := fixture(t)
	value, err := intent(s, list, selection(), scope(t, "vip"))
	if err != nil || value == nil {
		t.Fatal(value, err)
	}
	return *value
}

func payload(t *testing.T, issued time.Time, values []Intent) []byte {
	t.Helper()
	data, err := json.Marshal(Snapshot{Schema: 1, Issued: issued, Until: issued.Add(Lease), Services: values})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOnlyExternalVIPAndServicePortReachRecords(t *testing.T) {
	value := readyIntent(t)
	if value.ServicePort != 80 || !reflect.DeepEqual(value.Addresses, []string{"2001:db8:ff00::22"}) {
		t.Fatal(value)
	}
	now := catalog.Now()
	records, err := Records([]Intent{value}, now.Wall.Add(Lease), "kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"2001:db8:f004::123", "2001:db8:e000::10", "3000"} {
		if strings.Contains(string(data), private) {
			t.Fatal("backend detail escaped into discovery", private)
		}
	}
	for _, record := range records {
		if record.Type == "SRV" {
			rr, err := record.RR(15)
			if err != nil {
				t.Fatal(err)
			}
			if rr.(*dns.SRV).Port != 80 {
				t.Fatal("target port published")
			}
		}
	}
}

func TestUnreadyForeignAndUnexposedServicesWithdraw(t *testing.T) {
	for _, change := range []func(*service, []endpointSlice){
		func(s *service, _ []endpointSlice) { s.Spec.Type = "ClusterIP" }, func(s *service, _ []endpointSlice) { s.Spec.NotReady = true },
		func(s *service, _ []endpointSlice) { s.Metadata.Deleted = json.RawMessage(`"now"`) }, func(s *service, _ []endpointSlice) { s.Spec.Ports[0].Protocol = "UDP" },
		func(s *service, _ []endpointSlice) { s.Status.LoadBalancer.Ingress[0].Mode = "Proxy" }, func(s *service, _ []endpointSlice) { s.Status.LoadBalancer.Ingress[0].IP = "" },
		func(s *service, _ []endpointSlice) { s.Status.LoadBalancer.Ingress[0].IP = "2001:db8:f004::123" },
		func(_ *service, ls []endpointSlice) { ls[0].Metadata.Owners[0].UID = "old-uid" }, func(_ *service, ls []endpointSlice) { ls[0].Metadata.Namespace = "foreign" },
		func(_ *service, ls []endpointSlice) { ls[0].Ports[0].Name = "other" }, func(_ *service, ls []endpointSlice) { ls[0].Metadata.Deleted = json.RawMessage(`"now"`) },
		func(_ *service, ls []endpointSlice) { ls[0].Endpoints[0].Conditions.Ready = nil },
		func(_ *service, ls []endpointSlice) { value := false; ls[0].Endpoints[0].Conditions.Ready = &value },
		func(_ *service, ls []endpointSlice) { value := false; ls[0].Endpoints[0].Conditions.Serving = &value },
		func(_ *service, ls []endpointSlice) { ls[0].Endpoints[0].Conditions.Terminating = true },
	} {
		s, list := fixture(t)
		change(&s, list)
		value, err := intent(s, list, selection(), scope(t, "vip"))
		if err != nil || value != nil {
			t.Fatal("unexposed or unready Service advertised", value, err)
		}
	}
	// A badly configured broad pool still cannot publish the known backend or
	// ClusterIP as an external VIP.
	broad, err := policy.New(map[string][]string{"vip": {"2001:db8::/32"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"2001:db8:f004::123", "2001:db8:e000::10"} {
		s, list := fixture(t)
		s.Status.LoadBalancer.Ingress[0].IP = address
		value, err := intent(s, list, selection(), broad)
		if err != nil || value != nil {
			t.Fatal("backend/ClusterIP exported under broad VIP policy")
		}
	}
}

func TestDNSServiceNamesSubtypesAndUIDRecreation(t *testing.T) {
	now := catalog.Now().Wall
	value := readyIntent(t)
	value.Instance = "Web café . test"
	first, err := Records([]Intent{value}, now, "kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range first {
		rr, err := r.RR(1)
		if err != nil {
			t.Fatal(err)
		}
		if rr.Header().Rrtype == dns.TypeSRV {
			var buffer [256]byte
			n, err := dns.PackDomainName(r.Name, buffer[:], 0, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			label := string(buffer[1 : 1+int(buffer[0])])
			if !strings.HasPrefix(label, value.Instance+"-") || n == 0 {
				t.Fatal("instance label boundaries changed", r.Name)
			}
		}
	}
	value.UID = "recreated-uid"
	second, err := Records([]Intent{value}, now, "kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, second) {
		t.Fatal("recreated Service retained stale UID names")
	}
	value = readyIntent(t)
	other := value
	other.Name, other.UID = "another", "another-uid"
	all, err := Records([]Intent{value, other}, now, "kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range all {
		if r.Name == catalog.Enumeration {
			count++
		}
	}
	if count != 1 {
		t.Fatal("shared type enumeration duplicated", count)
	}
	for _, change := range []func(*Intent){
		func(v *Intent) { v.UID = "" }, func(v *Intent) { v.ServicePort = 0 }, func(v *Intent) { v.Addresses = []string{"2001:db8:f004::123"} },
		func(v *Intent) { v.Addresses = append(v.Addresses, "2001:0db8:ff00::22") },
	} {
		v := readyIntent(t)
		change(&v)
		if _, err := Records([]Intent{v}, now, "kubernetes", scope(t, "kubernetes")); err == nil {
			t.Fatal("invalid wire intent accepted")
		}
	}
}

func TestAbsoluteLeaseReplayClockFailureAndEmptyReplacement(t *testing.T) {
	now := catalog.Now()
	receiver, err := NewReceiver("kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	data := payload(t, now.Wall, []Intent{readyIntent(t)})
	if err := receiver.Install(data, now); err != nil {
		t.Fatal(err)
	}
	later := func(offset time.Duration) catalog.Moment {
		return catalog.Moment{Wall: now.Wall.Add(offset), Mono: now.Mono + offset}
	}
	if err := receiver.Install(data, later(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(receiver.Records(later(14*time.Second))) == 0 || len(receiver.Records(later(15*time.Second))) != 0 {
		t.Fatal("retransmission renewed absolute lease")
	}
	for _, data := range [][]byte{
		payload(t, now.Wall.Add(-time.Second), []Intent{readyIntent(t)}), payload(t, now.Wall, []Intent{}), []byte(`{}`),
		[]byte(strings.Replace(string(payload(t, now.Wall, []Intent{readyIntent(t)})), `"schema":1`, `"schema":true`, 1)),
	} {
		if err := receiver.Install(data, now); err == nil {
			t.Fatal("conflicting replay or malformed replacement accepted")
		}
	}
	for _, moment := range []catalog.Moment{{Wall: now.Wall, Mono: now.Mono - time.Second}, {Wall: now.Wall.Add(5 * time.Second), Mono: now.Mono + time.Second}} {
		if len(receiver.Records(moment)) != 0 {
			t.Fatal("clock discontinuity retained publication")
		}
	}
	if err := receiver.Install(payload(t, later(15*time.Second).Wall, []Intent{readyIntent(t)}), later(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(receiver.Records(later(16*time.Second))) == 0 {
		t.Fatal("renewal did not recover")
	}
	if err := receiver.Install(payload(t, later(17*time.Second).Wall, []Intent{}), later(17*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(receiver.Records(later(17*time.Second))) != 0 {
		t.Fatal("empty replacement did not withdraw")
	}
}

type scripted struct {
	calls                                 [][]string
	changed, paginated, insecure, missing bool
}

func (x *scripted) read(_ context.Context, argv []string) (json.RawMessage, error) {
	x.calls = append(x.calls, slices.Clone(argv))
	if slices.Contains(argv, "config") {
		if x.insecure {
			return json.RawMessage(`{"clusters":[{"cluster":{"server":"http://fixture"}}]}`), nil
		}
		return json.RawMessage(`{"clusters":[{"cluster":{"server":"https://fixture"}}]}`), nil
	}
	if !slices.Contains(argv, "get") {
		return nil, errors.New("non-read command")
	}
	if strings.Contains(argv[len(argv)-1], "endpointslices?") {
		items := sliceJSON
		if x.missing {
			items = ""
		}
		continued := ""
		if x.paginated {
			continued = "more"
		}
		return json.RawMessage(`{"kind":"EndpointSliceList","apiVersion":"discovery.k8s.io/v1","metadata":{"continue":"` + continued + `"},"items":[` + items + `]}`), nil
	}
	data := serviceJSON
	if x.changed && len(x.calls) == 4 {
		data = strings.Replace(data, `"resourceVersion":"10"`, `"resourceVersion":"11"`, 1)
	}
	return json.RawMessage(data), nil
}

func TestAPIReadsAreVerifiedCompleteStableAndReadOnly(t *testing.T) {
	x := &scripted{}
	configuration := settings()
	p, err := NewProducer(configuration, x.read)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Services[0].TXT["path"] = "/changed"
	configuration.Kubectl[0] = "/unavailable"
	value, err := p.Snapshot(context.Background())
	if err != nil || len(value.Services) != 1 || value.Services[0].TXT["path"] != "/" {
		t.Fatal(value, err)
	}
	if len(x.calls) != 4 {
		t.Fatal("unexpected API observation calls", x.calls)
	}
	for i, call := range x.calls {
		if call[0] != "/usr/bin/kubectl" || !slices.Contains(call, "--insecure-skip-tls-verify=false") || i > 0 && !slices.Contains(call, "get") {
			t.Fatal("unverified or mutating CLI observation", call)
		}
	}
	for _, failure := range []*scripted{{changed: true}, {paginated: true}, {insecure: true}} {
		p, err := NewProducer(settings(), failure.read)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Snapshot(context.Background()); err == nil {
			t.Fatal("incomplete/racing API read accepted")
		}
	}
	p, err = NewProducer(settings(), (&scripted{missing: true}).read)
	if err != nil {
		t.Fatal(err)
	}
	value, err = p.Snapshot(context.Background())
	if err != nil || len(value.Services) != 0 {
		t.Fatal("missing readiness did not produce empty replacement", value, err)
	}
}

func TestIPv4VIPProducesAWithoutPublishingEndpoints(t *testing.T) {
	s, list := fixture(t)
	s.Status.LoadBalancer.Ingress[0].IP = "192.0.2.22"
	p, err := policy.New(map[string][]string{"vip": {"192.0.2.0/24"}, "kubernetes": {"192.0.2.0/24"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, err := intent(s, list, selection(), p)
	if err != nil || value == nil {
		t.Fatal(value, err)
	}
	records, err := Records([]Intent{*value}, time.Now(), "kubernetes", p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range records {
		if r.Type == "A" && netip.MustParseAddr(r.Data).Is4() {
			found = true
		}
	}
	if !found {
		t.Fatal("configured IPv4 VIP omitted")
	}
}
