// Package config validates explicit operator inputs for each discovery process.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

const MaxBytes = 65536

// Endpoint is a numeric operator-selected HTTP endpoint.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Validate rejects implicit DNS, proxy or wildcard destinations.
func (e Endpoint) Validate() error {
	address, err := netip.ParseAddr(e.Host)
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" || address.Is4In6() || e.Port < 1 || e.Port > 65535 {
		return errors.New("numeric unicast gateway endpoint required")
	}
	return nil
}

// Rule is the independent operator selector in addition to the pod opt-in label.
type Rule struct {
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"service_account"`
	Labels         map[string]string `json:"match_labels"`
}

// Translation contains no installation defaults for synthesized address ranges.
type Translation struct {
	NAT64Prefix string   `json:"nat64_prefix"`
	NAT46Pool   string   `json:"nat46_pool"`
	Reserved    []string `json:"reserved"`
}

// Parse validates configured translation address spaces for feed admission.
func (t *Translation) Parse() (*catalog.Translation, error) {
	if t == nil {
		return nil, nil
	}
	nat64, err := netip.ParsePrefix(t.NAT64Prefix)
	if err != nil || !nat64.Addr().Is6() || nat64.Addr().Is4In6() || nat64.Bits() != 96 || nat64 != nat64.Masked() || nat64.Addr().IsMulticast() || nat64.Addr().IsLinkLocalUnicast() || nat64.Addr().IsLoopback() {
		return nil, errors.New("explicit NAT64 /96 required")
	}
	pool, err := netip.ParsePrefix(t.NAT46Pool)
	if err != nil || !pool.Addr().Is4() || pool != pool.Masked() || pool.Bits() < 8 || pool.Bits() > 30 || pool.Addr().IsMulticast() || pool.Addr().IsLoopback() || pool.Addr().IsLinkLocalUnicast() {
		return nil, errors.New("explicit bounded NAT46 pool required")
	}
	if len(t.Reserved) > 256 {
		return nil, errors.New("reserved address limit")
	}
	parsed := &catalog.Translation{NAT64: nat64, Pool: pool}
	seen := make(map[netip.Addr]bool)
	for _, raw := range t.Reserved {
		address, err := netip.ParseAddr(raw)
		if err != nil || !pool.Contains(address) || seen[address] {
			return nil, errors.New("invalid or duplicate reserved alias")
		}
		seen[address] = true
		parsed.Reserved = append(parsed.Reserved, address)
	}
	return parsed, nil
}

// Worker contains only the settings needed by an unprivileged responder.
type Worker struct {
	Gateway     Endpoint            `json:"gateway"`
	Sources     map[string][]string `json:"sources"`
	Forbidden   []string            `json:"forbidden"`
	Translation *Translation        `json:"translation,omitempty"`
}

// Policy validates immutable native and derived feed admission.
func (w Worker) Policy() (*policy.SourcePolicy, *catalog.Translation, error) {
	if err := w.Gateway.Validate(); err != nil {
		return nil, nil, err
	}
	t, err := w.Translation.Parse()
	if err != nil {
		return nil, nil, err
	}
	forbidden := append([]string{}, w.Forbidden...)
	if t != nil {
		forbidden = append(forbidden, t.NAT64.String(), t.Pool.String())
	}
	p, err := policy.New(w.Sources, forbidden)
	return p, t, err
}

// Node retains the existing node config fields and makes policy names explicit.
type Node struct {
	Enabled         bool     `json:"enabled"`
	Node            string   `json:"node"`
	Kubectl         []string `json:"kubectl"`
	Kubeconfig      string   `json:"kubeconfig"`
	Crictl          []string `json:"crictl"`
	RuntimeEndpoint string   `json:"runtime_endpoint"`
	HostProc        string   `json:"host_proc"`
	WorkerUID       uint32   `json:"worker_uid"`
	WorkerGID       uint32   `json:"worker_gid"`
	Rules           []Rule   `json:"rules"`
	OptInKey        string   `json:"opt_in_key,omitempty"`
	PodInterface    string   `json:"pod_interface,omitempty"`
	Worker
}

var resource = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

// Command accepts a standalone executable or an existing two-part CLI wrapper.
func Command(argv []string) bool {
	if len(argv) < 1 || len(argv) > 2 || !filepath.IsAbs(argv[0]) {
		return false
	}
	for _, part := range argv {
		if part == "" || strings.ContainsRune(part, '\x00') {
			return false
		}
	}
	return true
}

// Validate applies safe generic defaults only to names, never network ranges.
func (n *Node) Validate() error {
	if n.OptInKey == "" {
		n.OptInKey = "discovery-bridge-client"
	}
	if n.PodInterface == "" {
		n.PodInterface = "eth0"
	}
	if !n.Enabled || !resource.MatchString(n.Node) || !Command(n.Kubectl) || !Command(n.Crictl) || !filepath.IsAbs(n.Kubeconfig) || !filepath.IsAbs(n.HostProc) || !strings.HasPrefix(n.RuntimeEndpoint, "unix:///") || n.WorkerUID == 0 || n.WorkerGID == 0 || n.Rules == nil || len(n.Rules) > 64 || len(n.OptInKey) > 253 || strings.ContainsAny(n.OptInKey, "\x00\n ") || len(n.PodInterface) < 1 || len(n.PodInterface) > 15 || strings.ContainsAny(n.PodInterface, "/\x00\n ") {
		return errors.New("explicit enabled node configuration required")
	}
	for _, r := range n.Rules {
		if !resource.MatchString(r.Namespace) || !resource.MatchString(r.ServiceAccount) || len(r.Labels) < 1 || len(r.Labels) > 64 {
			return errors.New("explicit namespace, service account and workload labels required")
		}
		for key, value := range r.Labels {
			if key == "" || value == "" || key == n.OptInKey {
				return errors.New("admission rule must be independent of opt-in")
			}
		}
	}
	_, _, err := n.Policy()
	return err
}

// LoadNode reads one bounded config, optionally using the downward API node name.
func LoadNode(path, node string) (Node, error) {
	var n Node
	data, err := read(path)
	if err != nil {
		return n, err
	}
	if err := jsonwire.Decode(data, MaxBytes, &n); err != nil {
		return n, err
	}
	if node != "" {
		n.Node = node
	}
	err = n.Validate()
	return n, err
}

func read(path string) (data []byte, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute configuration path required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("configuration exceeds %d bytes", MaxBytes)
	}
	return data, nil
}
