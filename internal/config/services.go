package config

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/registry"
)

const MaxServices = 16

// Service selects one named external Service port and its public DNS-SD metadata.
type Service struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Port      string            `json:"port"`
	Type      string            `json:"type"`
	Instance  string            `json:"instance"`
	TXT       map[string]string `json:"txt"`
	Subtypes  []string          `json:"subtypes"`
}

var (
	serviceResource = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	txtKey          = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
	subtypeLabel    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}$`)
)

// Key identifies an explicit Service port selection independently of its UID.
func (s Service) Key() [3]string { return [3]string{s.Namespace, s.Name, s.Port} }

// Validate admits bounded metadata and RFC6335 types, including unknown types.
func (s Service) Validate() error {
	for _, value := range s.Key() {
		if !serviceResource.MatchString(value) {
			return errors.New("explicit Kubernetes resource and port names required")
		}
	}
	kind, err := registry.ObservedType(s.Type)
	if err != nil {
		return err
	}
	identifier, transport, ok := strings.Cut(kind, "._")
	generated, err := registry.GeneratedType(strings.TrimPrefix(identifier, "_"), transport)
	if !ok || err != nil || generated != kind {
		return errors.New("generated DNS-SD type must meet RFC6335")
	}
	if len(s.Instance) < 1 || len(s.Instance) > 32 || !utf8.ValidString(s.Instance) || strings.ContainsFunc(s.Instance, func(r rune) bool { return r < 32 }) || s.TXT == nil || len(s.TXT) > 16 || s.Subtypes == nil || len(s.Subtypes) > 8 {
		return errors.New("bounded public Service metadata required")
	}
	bytes := 0
	for key, value := range s.TXT {
		if !txtKey.MatchString(key) || !utf8.ValidString(value) || len(key)+1+len(value) > 255 {
			return errors.New("invalid public TXT field")
		}
		bytes += len(key) + len(value) + 2
	}
	if bytes > 1024 {
		return errors.New("public TXT byte limit")
	}
	seen := make(map[string]bool)
	for _, value := range s.Subtypes {
		key := strings.ToLower(value)
		if !subtypeLabel.MatchString(value) || seen[key] {
			return errors.New("invalid or duplicate subtype label")
		}
		seen[key] = true
	}
	return nil
}

// ServicePublisher configures one read-only Kubernetes producer and its VIP policy.
type ServicePublisher struct {
	Enabled     bool      `json:"enabled"`
	Kubectl     []string  `json:"kubectl"`
	Kubeconfig  string    `json:"kubeconfig"`
	Gateway     Endpoint  `json:"gateway"`
	VIPNetworks []string  `json:"vip_networks"`
	Forbidden   []string  `json:"forbidden"`
	Services    []Service `json:"services"`
}

// Policy parses independently configured VIP admission without network defaults.
func (s ServicePublisher) Policy() (*policy.SourcePolicy, error) {
	if len(s.VIPNetworks) == 0 || len(s.VIPNetworks) > 32 {
		return nil, errors.New("explicit bounded LoadBalancer VIP networks required")
	}
	return policy.New(map[string][]string{"vip": s.VIPNetworks}, s.Forbidden)
}

// Validate keeps publication opt-ins and endpoint authority explicit.
func (s ServicePublisher) Validate() error {
	if !s.Enabled || !Command(s.Kubectl) || !normalizedPath(s.Kubeconfig) || s.Services == nil || len(s.Services) > MaxServices {
		return errors.New("explicit enabled Service publisher required")
	}
	if err := s.Gateway.Validate(); err != nil {
		return err
	}
	if _, err := s.Policy(); err != nil {
		return err
	}
	seen := make(map[[3]string]bool)
	for _, service := range s.Services {
		if err := service.Validate(); err != nil {
			return err
		}
		if seen[service.Key()] {
			return errors.New("duplicate Service port selection")
		}
		seen[service.Key()] = true
	}
	return nil
}

// LoadServicePublisher reads strictly decoded bounded producer configuration.
func LoadServicePublisher(path string) (ServicePublisher, error) {
	var settings ServicePublisher
	data, err := read(path)
	if err != nil {
		return settings, err
	}
	if err := jsonwire.Decode(data, MaxBytes, &settings); err != nil {
		return settings, err
	}
	return settings, settings.Validate()
}

// PublicationListener admits publication separately from catalog/lookup clients.
// The source's VIP networks come from Router.Sources, without a second copy.
type PublicationListener struct {
	Listener
	Source string `json:"source"`
}

func (r Router) validatePublication(lanSources map[string]bool) error {
	p := r.Publication
	if p == nil {
		return nil
	}
	if !sourceName.MatchString(p.Source) || lanSources[p.Source] || len(r.Sources[p.Source]) == 0 || len(r.Sources[p.Source]) > 32 {
		return errors.New("publication requires a separate explicit VIP source")
	}
	if _, err := p.Prefixes(); err != nil {
		return err
	}
	if r.Gateway != nil && p.Port == r.Gateway.Port {
		publicationIP, err := netip.ParseAddr(p.Host)
		gatewayIP, gatewayErr := netip.ParseAddr(r.Gateway.Host)
		if err == nil && gatewayErr == nil && publicationIP == gatewayIP {
			return errors.New("publication and catalog listeners must be distinct")
		}
	}
	for _, raw := range r.Sources[p.Source] {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		for _, lan := range r.Interfaces {
			for _, native := range r.Sources[lan.Source] {
				other, err := netip.ParsePrefix(native)
				if err != nil || prefix.Overlaps(other) {
					return errors.New("VIP source cannot overlap a LAN observation scope")
				}
			}
		}
	}
	return nil
}
