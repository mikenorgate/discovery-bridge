package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func validNode() Node {
	return Node{Enabled: true, Node: "node-a", Kubectl: []string{"/usr/bin/kubectl"}, Kubeconfig: "/etc/discovery-bridge/kubeconfig", Crictl: []string{"/usr/bin/crictl"}, RuntimeEndpoint: "unix:///run/containerd/containerd.sock", HostProc: "/host/proc", WorkerUID: 65532, WorkerGID: 65532, Rules: []Rule{{Namespace: "apps", ServiceAccount: "discovery", Labels: map[string]string{"app": "automation"}}}, Worker: Worker{Gateway: Endpoint{Host: "2001:db8::1", Port: 9443}, Sources: map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, Forbidden: []string{}}}
}

func TestGenericConfigAndIndependentAdmission(t *testing.T) {
	n := validNode()
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadNode(path, "node-b")
	if err != nil || loaded.Node != "node-b" || loaded.OptInKey != "discovery-bridge-client" || loaded.PodInterface != "eth0" {
		t.Fatal(loaded, err)
	}
	loaded.Rules[0].Labels = map[string]string{loaded.OptInKey: "true"}
	if err := loaded.Validate(); err == nil {
		t.Fatal("opt-in replaced independent operator rule")
	}
}

func TestTranslationMustHaveExplicitSpaces(t *testing.T) {
	n := validNode()
	n.Translation = &Translation{}
	if err := n.Validate(); err == nil {
		t.Fatal("translation guessed network ranges")
	}
	n.Translation = &Translation{NAT64Prefix: "2001:db8:64::/96", NAT46Pool: "198.51.100.0/24", Reserved: []string{"198.51.100.1"}}
	n.Sources["lan-a"] = append(n.Sources["lan-a"], "2001:db8::/32")
	p, translated, err := n.Policy()
	if err != nil || translated == nil {
		t.Fatal(err)
	}
	if err := p.CheckAddress("lan-a", netip.MustParseAddr("2001:db8:64::c000:22a")); err == nil {
		t.Fatal("native feed admitted synthetic address")
	}
}
