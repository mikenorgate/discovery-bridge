package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/node"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/registry"
)

type metadata struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	UID       string            `json:"uid"`
	Version   string            `json:"resourceVersion"`
	Deleted   json.RawMessage   `json:"deletionTimestamp"`
	Labels    map[string]string `json:"labels"`
	Owners    []struct {
		Kind       string `json:"kind"`
		UID        string `json:"uid"`
		Controller bool   `json:"controller"`
	} `json:"ownerReferences"`
}

type port struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type service struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Metadata   metadata `json:"metadata"`
	Spec       struct {
		Type       string   `json:"type"`
		NotReady   bool     `json:"publishNotReadyAddresses"`
		Ports      []port   `json:"ports"`
		ClusterIP  string   `json:"clusterIP"`
		ClusterIPs []string `json:"clusterIPs"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP   string `json:"ip"`
				Mode string `json:"ipMode"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type endpointSlice struct {
	Metadata    metadata `json:"metadata"`
	AddressType string   `json:"addressType"`
	Ports       []port   `json:"ports"`
	Endpoints   []struct {
		Addresses  []string `json:"addresses"`
		Conditions struct {
			Ready       *bool `json:"ready"`
			Serving     *bool `json:"serving"`
			Terminating bool  `json:"terminating"`
		} `json:"conditions"`
	} `json:"endpoints"`
}

func deleted(value json.RawMessage) bool { return len(value) > 0 && string(value) != "null" }
func protocol(value string) string {
	if value == "" {
		return "TCP"
	}
	return value
}

func intent(s service, endpointSlices []endpointSlice, selected config.Service, scopes *policy.SourcePolicy) (*Intent, error) {
	if err := selected.Validate(); err != nil {
		return nil, err
	}
	meta, spec := s.Metadata, s.Spec
	if meta.Namespace != selected.Namespace || meta.Name != selected.Name || deleted(meta.Deleted) || spec.Type != "LoadBalancer" || spec.NotReady {
		return nil, nil
	}
	kind, err := registry.ObservedType(selected.Type)
	if err != nil {
		return nil, err
	}
	transport := strings.ToUpper(kind[strings.LastIndex(kind, "._")+2:])
	var selectedPorts []port
	for _, p := range spec.Ports {
		if p.Name == selected.Port && protocol(p.Protocol) == transport {
			selectedPorts = append(selectedPorts, p)
		}
	}
	if len(selectedPorts) != 1 || selectedPorts[0].Port < 1 || selectedPorts[0].Port > 65535 {
		return nil, nil
	}
	ready, backends := false, make(map[netip.Addr]bool)
	for _, item := range endpointSlices {
		if len(item.Endpoints) > 4096 || len(item.Ports) > 64 {
			return nil, errors.New("EndpointSlice entry limit")
		}
		owned := false
		for _, owner := range item.Metadata.Owners {
			owned = owned || owner.Kind == "Service" && owner.UID == meta.UID && owner.Controller
		}
		if !owned || item.Metadata.Namespace != meta.Namespace || deleted(item.Metadata.Deleted) || item.Metadata.Labels["kubernetes.io/service-name"] != meta.Name || item.AddressType != "IPv4" && item.AddressType != "IPv6" {
			continue
		}
		matched := false
		for _, p := range item.Ports {
			matched = matched || p.Name == selected.Port && protocol(p.Protocol) == transport && p.Port > 0 && p.Port <= 65535
		}
		for _, endpoint := range item.Endpoints {
			if len(endpoint.Addresses) > 100 {
				return nil, errors.New("EndpointSlice address limit")
			}
			for _, raw := range endpoint.Addresses {
				address, err := netip.ParseAddr(raw)
				if err != nil || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsLinkLocalUnicast() || (address.Is4() != (item.AddressType == "IPv4")) {
					return nil, errors.New("invalid endpoint address")
				}
				backends[address] = true
			}
			conditions := endpoint.Conditions
			ready = ready || matched && conditions.Ready != nil && *conditions.Ready && (conditions.Serving == nil || *conditions.Serving) && !conditions.Terminating && len(endpoint.Addresses) > 0
		}
	}
	if !ready {
		return nil, nil
	}
	addresses := make(map[netip.Addr]bool)
	if len(s.Status.LoadBalancer.Ingress) > 64 {
		return nil, errors.New("LoadBalancer ingress limit")
	}
	cluster := make(map[netip.Addr]bool)
	for _, raw := range append(slices.Clone(spec.ClusterIPs), spec.ClusterIP) {
		if address, err := netip.ParseAddr(raw); err == nil {
			cluster[address] = true
		}
	}
	for _, entry := range s.Status.LoadBalancer.Ingress {
		if entry.IP == "" || entry.Mode != "" && entry.Mode != "VIP" {
			continue
		}
		address, err := netip.ParseAddr(entry.IP)
		if err != nil {
			return nil, err
		}
		if scopes.CheckAddress("vip", address) == nil && !backends[address] && !cluster[address] {
			addresses[address] = true
		}
	}
	if len(addresses) == 0 {
		return nil, nil
	}
	if len(addresses) > 4 {
		return nil, errors.New("LoadBalancer VIP limit")
	}
	values := make([]string, 0, len(addresses))
	for address := range addresses {
		values = append(values, address.String())
	}
	slices.Sort(values)
	return &Intent{Service: selected, UID: meta.UID, Addresses: values, ServicePort: selectedPorts[0].Port}, nil
}

// Producer uses the same bounded read-only CLI adapter as the node broker.
type Producer struct {
	selected []config.Service
	argv     []string
	scopes   *policy.SourcePolicy
	read     node.ReadJSON
	checked  bool // Snapshot has a single owner, the producer loop.
}

// NewProducer copies configuration and permits injected CLI observations in tests.
func NewProducer(settings config.ServicePublisher, read node.ReadJSON) (*Producer, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	scopes, err := settings.Policy()
	if err != nil {
		return nil, err
	}
	selected := make([]config.Service, 0, len(settings.Services))
	for _, value := range settings.Services {
		copy := value
		copy.TXT = make(map[string]string, len(value.TXT))
		for key, v := range value.TXT {
			copy.TXT[key] = v
		}
		copy.Subtypes = append([]string{}, value.Subtypes...)
		selected = append(selected, copy)
	}
	if read == nil {
		read = node.CommandJSON
	}
	argv := append(slices.Clone(settings.Kubectl), "--kubeconfig", settings.Kubeconfig, "--request-timeout=2s", "--insecure-skip-tls-verify=false")
	return &Producer{selected: selected, argv: argv, scopes: scopes, read: read}, nil
}

// Snapshot samples Service identity before and after complete EndpointSlice reads.
// A slow observation cannot issue a new lease after its first data has expired.
func (p *Producer) Snapshot(ctx context.Context) (Snapshot, error) {
	if !p.checked {
		if err := node.CheckTLS(ctx, p.read, p.argv); err != nil {
			return Snapshot{}, err
		}
		p.checked = true
	}
	observed := catalog.Now()
	bounded, cancel := context.WithTimeout(ctx, Lease-2*time.Second)
	defer cancel()
	result := Snapshot{Schema: 1, Issued: observed.Wall, Until: observed.Wall.Add(Lease), Services: make([]Intent, 0)}
	read := func(path string) ([]byte, error) {
		return p.read(bounded, append(slices.Clone(p.argv), "get", "--raw="+path))
	}
	for _, selected := range p.selected {
		path := "/api/v1/namespaces/" + selected.Namespace + "/services/" + selected.Name
		data, err := read(path)
		if err != nil {
			return Snapshot{}, err
		}
		var before service
		if err := json.Unmarshal(data, &before); err != nil {
			return Snapshot{}, err
		}
		data, err = read("/apis/discovery.k8s.io/v1/namespaces/" + selected.Namespace + "/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D" + selected.Name)
		if err != nil {
			return Snapshot{}, err
		}
		var list struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
			Metadata   struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []endpointSlice `json:"items"`
		}
		if err := json.Unmarshal(data, &list); err != nil || list.Kind != "EndpointSliceList" || list.APIVersion != "discovery.k8s.io/v1" || list.Metadata.Continue != "" || list.Items == nil || len(list.Items) > 256 {
			return Snapshot{}, errors.New("complete bounded EndpointSlice list required")
		}
		data, err = read(path)
		if err != nil {
			return Snapshot{}, err
		}
		var after service
		if err := json.Unmarshal(data, &after); err != nil || before.Kind != "Service" || before.APIVersion != "v1" || after.Kind != before.Kind || after.APIVersion != before.APIVersion || before.Metadata.Version == "" || before.Metadata.Version != after.Metadata.Version || before.Metadata.UID != after.Metadata.UID || !serviceUID.MatchString(after.Metadata.UID) {
			return Snapshot{}, errors.New("service identity changed during observation")
		}
		value, err := intent(after, list.Items, selected, p.scopes)
		if err != nil {
			return Snapshot{}, err
		}
		if value != nil {
			result.Services = append(result.Services, *value)
		}
	}
	if bounded.Err() != nil {
		return Snapshot{}, bounded.Err()
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > gateway.MaxRequestBytes {
		return Snapshot{}, errors.New("service publication byte limit")
	}
	return result, nil
}
