package config

import (
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

// LAN ties a configurable interface to one source identity and explicit families.
type LAN struct {
	Interface string `json:"interface"`
	Source    string `json:"source"`
	Families  []int  `json:"families"`
}

// Listener is a numeric unicast HTTP bind with independently admitted client ranges.
type Listener struct {
	Endpoint
	Clients []string `json:"clients"`
}

// Prefixes validates the listener and returns copies of bounded client prefixes.
func (l Listener) Prefixes() ([]netip.Prefix, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if len(l.Clients) < 1 || len(l.Clients) > 32 {
		return nil, errors.New("explicit bounded gateway client ranges required")
	}
	var result []netip.Prefix
	for _, value := range l.Clients {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid gateway client range")
		}
		result = append(result, prefix)
	}
	return result, nil
}

// Bootstrap supplies generic browse demand in addition to standard enumeration.
type Bootstrap struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Router contains operator-owned topology, paths and local producer authority.
// Translator readiness and Service publication have separate explicit settings.
type Router struct {
	Enabled         bool                `json:"enabled"`
	Interfaces      []LAN               `json:"interfaces"`
	Sources         map[string][]string `json:"sources"`
	Forbidden       []string            `json:"forbidden"`
	AliasPrefix     string              `json:"alias_prefix"`
	BusSocket       string              `json:"bus_socket"`
	State           string              `json:"state"`
	PublisherSocket string              `json:"publisher_socket"`
	ProducerUser    string              `json:"producer_user"`
	Gateway         *Listener           `json:"gateway,omitempty"`
	Bootstrap       []Bootstrap         `json:"bootstrap,omitempty"`
}

var (
	aliasPrefix = regexp.MustCompile(`^[a-z][a-z0-9-]{0,7}$`)
	sourceName  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	account     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// Policy validates the explicit native source and excluded network policy.
func (r Router) Policy() (*policy.SourcePolicy, error) { return policy.New(r.Sources, r.Forbidden) }

// Validate rejects implicit topology, paths, publication authority or listeners.
func (r Router) Validate() error {
	if !r.Enabled || len(r.Interfaces) == 0 || len(r.Interfaces) > 12 || !aliasPrefix.MatchString(r.AliasPrefix) || !filepath.IsAbs(r.State) || !account.MatchString(r.ProducerUser) || len(r.Bootstrap) > 64 {
		return errors.New("explicit enabled router configuration required")
	}
	for _, path := range []string{r.BusSocket, r.PublisherSocket} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
			return errors.New("absolute local Unix socket path required")
		}
	}
	if filepath.Clean(r.State) != r.State || r.BusSocket == r.PublisherSocket || r.State == r.BusSocket || r.State == r.PublisherSocket {
		return errors.New("distinct normalized router state and socket paths required")
	}
	interfaces, sources := make(map[string]bool), make(map[string]bool)
	groups := 0
	for _, lan := range r.Interfaces {
		if len(lan.Interface) == 0 || len(lan.Interface) > 15 || strings.ContainsAny(lan.Interface, "/\x00\n ") || !sourceName.MatchString(lan.Source) || interfaces[lan.Interface] || sources[lan.Source] || len(r.Sources[lan.Source]) == 0 || len(lan.Families) == 0 || len(lan.Families) > 2 || slices.ContainsFunc(lan.Families, func(family int) bool { return family != 4 && family != 6 }) || len(lan.Families) == 2 && lan.Families[0] == lan.Families[1] {
			return errors.New("distinct admitted LAN interfaces, sources and IP families required")
		}
		groups += len(lan.Families)
		interfaces[lan.Interface], sources[lan.Source] = true, true
	}
	if groups > 12 {
		return errors.New("router publication group budget exceeded")
	}
	for source := range r.Sources {
		if !sourceName.MatchString(source) {
			return errors.New("invalid source identity")
		}
	}
	for _, question := range r.Bootstrap {
		if !catalog.LocalName(question.Name) || question.Type != "A" && question.Type != "AAAA" && question.Type != "PTR" && question.Type != "SRV" && question.Type != "TXT" {
			return errors.New("bootstrap requires supported .local questions")
		}
	}
	if r.Gateway != nil {
		if _, err := r.Gateway.Prefixes(); err != nil {
			return err
		}
	}
	_, err := r.Policy()
	return err
}

// LoadRouter reads one bounded, strictly decoded operator configuration.
func LoadRouter(path string) (Router, error) {
	var r Router
	data, err := read(path)
	if err != nil {
		return r, err
	}
	if err := jsonwire.Decode(data, MaxBytes, &r); err != nil {
		return r, err
	}
	return r, r.Validate()
}
