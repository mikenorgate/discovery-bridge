// Package node manages broker-owned pod admission and unprivileged responders.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/command"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
)

// ReadJSON is an injectable read-only CLI adapter used by brokers and publishers.
type ReadJSON func(context.Context, []string) (json.RawMessage, error)

// CommandJSON bounds command lifetime, output and descendants without a shell.
func CommandJSON(ctx context.Context, argv []string) (json.RawMessage, error) {
	data, err := command.Run(ctx, argv, 3*time.Second, 4_194_304)
	if err != nil {
		return nil, err
	}
	var value map[string]json.RawMessage
	if err := jsonwire.Decode(data, 4_194_304, &value); err != nil {
		return nil, errors.New("invalid command JSON")
	}
	return json.RawMessage(data), nil
}

type metadata struct {
	UID       string            `json:"uid"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
	Deletion  json.RawMessage   `json:"deletionTimestamp"`
}

type podObject struct {
	Metadata metadata `json:"metadata"`
	Spec     struct {
		Node           string `json:"nodeName"`
		HostNetwork    bool   `json:"hostNetwork"`
		ServiceAccount string `json:"serviceAccountName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
		IPs   []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
	} `json:"status"`
}

// Pod is an API-selected workload identity and its routable address set.
type Pod struct {
	UID, Name, Namespace string
	Addresses            []netip.Addr
}

func podAddresses(values []string) ([]netip.Addr, error) {
	if len(values) < 1 || len(values) > 2 {
		return nil, errors.New("bounded pod address set required")
	}
	result := make([]netip.Addr, 0, len(values))
	families := make(map[bool]bool)
	for _, text := range values {
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() || families[address.Is6()] {
			return nil, errors.New("invalid or duplicate pod address family")
		}
		families[address.Is6()] = true
		result = append(result, address)
	}
	if !families[true] {
		return nil, errors.New("IPv6 pod address required")
	}
	slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
	return result, nil
}

func deleted(value json.RawMessage) bool { return len(value) > 0 && string(value) != "null" }

// Select requires both the explicit pod label and an independent operator rule.
func Select(value json.RawMessage, settings config.Node) (Pod, bool) {
	var object podObject
	if err := json.Unmarshal(value, &object); err != nil {
		return Pod{}, false
	}
	meta, spec, status := object.Metadata, object.Spec, object.Status
	if meta.UID == "" || len(meta.UID) > 128 || meta.Name == "" || meta.Namespace == "" || spec.Node != settings.Node || spec.HostNetwork || deleted(meta.Deletion) || status.Phase != "Running" || meta.Labels[settings.OptInKey] != "true" {
		return Pod{}, false
	}
	approved := false
	for _, rule := range settings.Rules {
		if rule.Namespace != meta.Namespace || rule.ServiceAccount != spec.ServiceAccount {
			continue
		}
		matches := true
		for key, value := range rule.Labels {
			if meta.Labels[key] != value {
				matches = false
				break
			}
		}
		approved = approved || matches
	}
	if !approved {
		return Pod{}, false
	}
	var addresses []string
	for _, item := range status.IPs {
		addresses = append(addresses, item.IP)
	}
	ips, err := podAddresses(addresses)
	if err != nil {
		return Pod{}, false
	}
	return Pod{meta.UID, meta.Name, meta.Namespace, ips}, true
}

// Pods reads fresh complete own-node API lists using existing kubectl credentials.
type Pods struct {
	settings config.Node
	argv     []string
	read     ReadJSON
	checked  bool
}

// NewPods creates a fixed read-only Kubernetes command adapter.
func NewPods(settings config.Node, read ReadJSON) *Pods {
	argv := append(slices.Clone(settings.Kubectl), "--kubeconfig", settings.Kubeconfig, "--request-timeout=2s", "--insecure-skip-tls-verify=false")
	return &Pods{settings: settings, argv: argv, read: read}
}

// CheckTLS rejects an unverified or non-HTTPS Kubernetes connection.
func CheckTLS(ctx context.Context, read ReadJSON, argv []string) error {
	data, err := read(ctx, append(slices.Clone(argv), "config", "view", "--minify", "--output=json"))
	if err != nil {
		return err
	}
	var value struct {
		Clusters []struct {
			Cluster struct {
				Server   string `json:"server"`
				Insecure bool   `json:"insecure-skip-tls-verify"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(data, &value); err != nil || len(value.Clusters) != 1 || !strings.HasPrefix(value.Clusters[0].Cluster.Server, "https://") || value.Clusters[0].Cluster.Insecure {
		return errors.New("verified HTTPS Kubernetes endpoint required")
	}
	return nil
}

// Snapshot timestamps the start of the API read; failures never refresh a lease.
func (p *Pods) Snapshot(ctx context.Context) ([]json.RawMessage, time.Duration, error) {
	if !p.checked {
		if err := CheckTLS(ctx, p.read, p.argv); err != nil {
			return nil, 0, err
		}
		p.checked = true
	}
	observed := catalog.Now().Mono
	data, err := p.read(ctx, append(slices.Clone(p.argv), "get", "--raw=/api/v1/pods?fieldSelector=spec.nodeName%3D"+p.settings.Node))
	if err != nil {
		return nil, observed, err
	}
	var value struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Metadata   struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &value); err != nil || (value.Kind != "PodList" && value.Kind != "List") || value.APIVersion != "v1" || value.Metadata.Continue != "" || value.Items == nil || len(value.Items) > 4096 {
		return nil, observed, errors.New("complete bounded own-node pod list required")
	}
	for _, raw := range value.Items {
		var object podObject
		if err := json.Unmarshal(raw, &object); err != nil || object.Spec.Node != p.settings.Node {
			return nil, observed, errors.New("API returned an invalid or foreign-node pod")
		}
	}
	return value.Items, observed, nil
}

// Sandbox is a ready containerd sandbox independently matching the API identity.
type Sandbox struct {
	ID  string
	PID int
	Pod Pod
}

var sandboxID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Runtime verifies containerd's sandbox metadata and namespace state.
type Runtime struct {
	argv []string
	read ReadJSON
}

// NewRuntime creates a fixed local crictl adapter.
func NewRuntime(settings config.Node, read ReadJSON) *Runtime {
	return &Runtime{argv: append(slices.Clone(settings.Crictl), "--runtime-endpoint", settings.RuntimeEndpoint, "--timeout=2s"), read: read}
}

// Inspect rejects ambiguous, stopped or replaced sandbox identities.
func (r *Runtime) Inspect(ctx context.Context, pod Pod) (Sandbox, error) {
	data, err := r.read(ctx, append(slices.Clone(r.argv), "pods", "--state=ready", "--output=json"))
	if err != nil {
		return Sandbox{}, err
	}
	var list struct {
		Items []struct {
			ID       string   `json:"id"`
			Metadata metadata `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil || list.Items == nil || len(list.Items) > 4096 {
		return Sandbox{}, errors.New("invalid runtime sandbox list")
	}
	var matches []string
	for _, item := range list.Items {
		if item.Metadata.UID == pod.UID {
			matches = append(matches, item.ID)
		}
	}
	if len(matches) != 1 || !sandboxID.MatchString(matches[0]) {
		return Sandbox{}, errors.New("unique ready sandbox required")
	}
	data, err = r.read(ctx, append(slices.Clone(r.argv), "inspectp", "--output=json", matches[0]))
	if err != nil {
		return Sandbox{}, err
	}
	var value struct {
		Status struct {
			ID       string   `json:"id"`
			Metadata metadata `json:"metadata"`
			State    string   `json:"state"`
			Network  struct {
				IP         string `json:"ip"`
				Additional []struct {
					IP string `json:"ip"`
				} `json:"additionalIps"`
			} `json:"network"`
			Linux struct {
				Namespaces struct {
					Options struct {
						Network string `json:"network"`
					} `json:"options"`
				} `json:"namespaces"`
			} `json:"linux"`
		} `json:"status"`
		Info struct {
			PID     int    `json:"pid"`
			Process string `json:"processStatus"`
			Closed  *bool  `json:"netNamespaceClosed"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return Sandbox{}, errors.New("invalid runtime sandbox status")
	}
	status, info := value.Status, value.Info
	if status.ID != matches[0] || status.Metadata.UID != pod.UID || status.Metadata.Name != pod.Name || status.Metadata.Namespace != pod.Namespace || status.State != "SANDBOX_READY" || status.Linux.Namespaces.Options.Network != "POD" || info.PID <= 1 || info.Process != "running" || info.Closed == nil || *info.Closed {
		return Sandbox{}, errors.New("sandbox identity or state rejected")
	}
	addresses := []string{status.Network.IP}
	for _, item := range status.Network.Additional {
		addresses = append(addresses, item.IP)
	}
	actual, err := podAddresses(addresses)
	if err != nil || !slices.Equal(actual, pod.Addresses) {
		return Sandbox{}, errors.New("API and runtime addresses differ")
	}
	return Sandbox{status.ID, info.PID, pod}, nil
}
