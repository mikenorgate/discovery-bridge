package node

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/mikenorgate/discovery-bridge/internal/config"
)

func testSettings(t *testing.T) config.Node {
	t.Helper()
	n := config.Node{Enabled: true, Node: "node-a", Kubectl: []string{"/usr/bin/kubectl"}, Kubeconfig: "/etc/discovery-bridge/kubeconfig", Crictl: []string{"/usr/bin/crictl"}, RuntimeEndpoint: "unix:///run/containerd/containerd.sock", HostProc: "/proc", WorkerUID: 65532, WorkerGID: 65532, Rules: []config.Rule{{Namespace: "apps", ServiceAccount: "discovery", Labels: map[string]string{"app": "automation"}}}, Worker: config.Worker{Gateway: config.Endpoint{Host: "2001:db8::1", Port: 9443}, Sources: map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, Forbidden: []string{}}}
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	return n
}

const selectedPod = `{"metadata":{"uid":"pod-1","name":"automation","namespace":"apps","labels":{"app":"automation","discovery-bridge-client":"true"}},"spec":{"nodeName":"node-a","serviceAccountName":"discovery","hostNetwork":false},"status":{"phase":"Running","podIPs":[{"ip":"2001:db8:1::42"}]}}`

func TestPodAdmissionRequiresIndependentIdentityAndIPv6(t *testing.T) {
	settings := testSettings(t)
	pod, ok := Select([]byte(selectedPod), settings)
	if !ok || pod.UID != "pod-1" || len(pod.Addresses) != 1 {
		t.Fatal(pod, ok)
	}
	for _, change := range [][2]string{{`"true"`, `"false"`}, {`"serviceAccountName":"discovery"`, `"serviceAccountName":"other"`}, {`"app":"automation"`, `"app":"other"`}, {`"nodeName":"node-a"`, `"nodeName":"node-b"`}, {`"hostNetwork":false`, `"hostNetwork":true`}, {`"Running"`, `"Pending"`}, {`"2001:db8:1::42"`, `"192.0.2.42"`}, {`"2001:db8:1::42"`, `"fe80::42"`}, {`"uid":"pod-1"`, `"uid":""`}} {
		bad := strings.Replace(selectedPod, change[0], change[1], 1)
		if pod, ok := Select([]byte(bad), settings); ok {
			t.Fatal("unapproved pod admitted", pod)
		}
	}
	settings.OptInKey = "custom-discovery-opt-in"
	if _, ok := Select([]byte(selectedPod), settings); ok {
		t.Fatal("old label bypassed configured opt-in")
	}
	if _, ok := Select([]byte(strings.ReplaceAll(selectedPod, "discovery-bridge-client", "custom-discovery-opt-in")), settings); !ok {
		t.Fatal("configured label was ignored")
	}
}

func TestRuntimeStateAndAPIIdentityMustAgree(t *testing.T) {
	settings := testSettings(t)
	pod, ok := Select([]byte(selectedPod), settings)
	if !ok {
		t.Fatal("fixture selection failed")
	}
	id := strings.Repeat("a", 64)
	status := `{"status":{"id":"` + id + `","state":"SANDBOX_READY","metadata":{"uid":"pod-1","name":"automation","namespace":"apps"},"network":{"ip":"2001:db8:1::42"},"linux":{"namespaces":{"options":{"network":"POD"}}}},"info":{"pid":1234,"processStatus":"running","netNamespaceClosed":false}}`
	read := func(_ context.Context, argv []string) (json.RawMessage, error) {
		if argv[len(argv)-1] == id {
			return []byte(status), nil
		}
		return []byte(`{"items":[{"id":"` + id + `","metadata":{"uid":"pod-1"}}]}`), nil
	}
	runtime := NewRuntime(settings, read)
	sandbox, err := runtime.Inspect(context.Background(), pod)
	if err != nil || sandbox.PID != 1234 || sandbox.ID != id {
		t.Fatal(sandbox, err)
	}
	original := status
	for _, change := range [][2]string{{`"POD"`, `"NODE"`}, {`"pid":1234`, `"pid":1`}, {`"SANDBOX_READY"`, `"SANDBOX_NOTREADY"`}, {`"netNamespaceClosed":false`, `"netNamespaceClosed":true`}, {`"netNamespaceClosed":false`, `"netNamespaceClosed":null`}, {`"2001:db8:1::42"`, `"2001:db8:1::43"`}, {`"uid":"pod-1"`, `"uid":"pod-2"`}} {
		status = strings.Replace(original, change[0], change[1], 1)
		if _, err := runtime.Inspect(context.Background(), pod); err == nil {
			t.Fatal("invalid sandbox admitted", change)
		}
	}
	status = original
	pod.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8:1::43")}
	if _, err := runtime.Inspect(context.Background(), pod); err == nil {
		t.Fatal("runtime ignored selected API addresses")
	}
}

func TestCompleteOwnNodeListAndTLS(t *testing.T) {
	settings := testSettings(t)
	tls := `{"clusters":[{"cluster":{"server":"https://api.example","insecure-skip-tls-verify":false}}]}`
	pods := `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[` + selectedPod + `]}`
	read := func(_ context.Context, argv []string) (json.RawMessage, error) {
		if argv[len(argv)-1] == "--output=json" {
			return []byte(tls), nil
		}
		if !strings.Contains(argv[len(argv)-1], "spec.nodeName%3Dnode-a") {
			t.Fatal("unscoped API read", argv)
		}
		return []byte(pods), nil
	}
	p := NewPods(settings, read)
	items, observed, err := p.Snapshot(context.Background())
	if err != nil || len(items) != 1 || observed <= 0 {
		t.Fatal(items, observed, err)
	}
	pods = strings.Replace(pods, `"metadata":{}`, `"metadata":{"continue":"next-page"}`, 1)
	if _, _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatal("partial list renewed eligibility")
	}
	tls = strings.Replace(tls, `false`, `true`, 1)
	if _, _, err := NewPods(settings, read).Snapshot(context.Background()); err == nil {
		t.Fatal("unverified API endpoint accepted")
	}
}
