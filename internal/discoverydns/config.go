// Package discoverydns serves RFC 8766 authoritative zones backed by native mDNS.
// Recursion, ordinary DNS caching and DNS64 belong to the upstream resolver.
package discoverydns

import (
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
)

// Link maps one LAN source to service/host domains and reverse delegations.
type Link struct {
	Source        string   `json:"source"`
	ServiceDomain string   `json:"service_domain"`
	HostDomain    string   `json:"host_domain"`
	Prefixes      []string `json:"prefixes"`
}

// Config contains operator-owned authority and client scopes, never device data.
type Config struct {
	Schema           int               `json:"schema"`
	Enabled          bool              `json:"enabled"`
	Listeners        []config.Endpoint `json:"listeners"`
	Clients          []string          `json:"clients"`
	NativeSocket     string            `json:"native_socket"`
	CollectorUser    string            `json:"collector_user"`
	Nameservers      []string          `json:"nameservers"`
	Mailbox          string            `json:"mailbox"`
	DefaultSource    string            `json:"default_source"`
	Links            []Link            `json:"links"`
	SuppressUnusable *bool             `json:"suppress_unusable,omitempty"`
}

type zone struct {
	name      string
	link      int
	isReverse bool
	isHost    bool
}

func domain(name string) bool {
	if !dnswire.Name(name) || name == "." || dns.IsSubDomain("local.", name) {
		return false
	}
	return !dns.IsSubDomain("arpa.", name)
}

func ldh(name string) bool {
	for _, label := range dns.SplitDomainName(name) {
		if len(label) == 0 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, value := range []byte(label) {
			letter := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
			digit := value >= '0' && value <= '9'
			if !letter && !digit && value != '-' {
				return false
			}
		}
	}
	return true
}

// Validate rejects ambiguous delegation, implicit clients and wildcard listeners.
func (c Config) Validate() error {
	if c.Schema != 1 || !c.Enabled || len(c.Listeners) < 1 || len(c.Listeners) > 4 || len(c.Links) < 1 || len(c.Links) > 12 {
		return errors.New("discovery dns: explicit enabled schema and topology required")
	}
	if !filepath.IsAbs(c.NativeSocket) || filepath.Clean(c.NativeSocket) != c.NativeSocket || len(c.NativeSocket) > 107 {
		return errors.New("discovery dns: absolute native socket required")
	}
	if c.CollectorUser == "" || c.CollectorUser == "root" || strings.ContainsAny(c.CollectorUser, "/\x00\n ") {
		return errors.New("discovery dns: unprivileged collector account required")
	}
	if len(c.Clients) < 1 || len(c.Clients) > 128 || len(c.Nameservers) < 1 || len(c.Nameservers) > 8 || !domain(c.Mailbox) {
		return errors.New("discovery dns: explicit clients, nameservers and mailbox required")
	}
	for _, endpoint := range c.Listeners {
		if err := endpoint.Validate(); err != nil {
			return err
		}
	}
	for _, raw := range c.Clients {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() {
			return errors.New("discovery dns: invalid client prefix")
		}
	}
	sources, domains := make(map[string]bool), make(map[string]bool)
	allPrefixes := []netip.Prefix{}
	for _, link := range c.Links {
		if link.Source == "" || len(link.Source) > 128 || sources[link.Source] || !domain(link.ServiceDomain) || !domain(link.HostDomain) {
			return errors.New("discovery dns: distinct sources and absolute discovery domains required")
		}
		if catalog.NameKey(link.ServiceDomain) != catalog.NameKey(link.HostDomain) && !ldh(link.HostDomain) {
			return errors.New("discovery dns: separate host domain must contain ldh labels")
		}
		sources[link.Source] = true
		for _, name := range slices.Compact([]string{catalog.NameKey(link.ServiceDomain), catalog.NameKey(link.HostDomain)}) {
			if domains[name] {
				return errors.New("discovery dns: duplicate delegated domain")
			}
			for other := range domains {
				if dns.IsSubDomain(other, name) || dns.IsSubDomain(name, other) {
					return errors.New("discovery dns: nested delegated domains are ambiguous")
				}
			}
			domains[name] = true
		}
		if len(link.Prefixes) < 1 || len(link.Prefixes) > 8 {
			return errors.New("discovery dns: bounded source prefixes required")
		}
		for _, raw := range link.Prefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
				return errors.New("discovery dns: invalid source prefix")
			}
			if _, err := dnswire.ReverseZone(prefix); err != nil {
				return err
			}
			for _, other := range allPrefixes {
				if prefix.Overlaps(other) {
					return errors.New("discovery dns: overlapping source reverse delegations")
				}
			}
			allPrefixes = append(allPrefixes, prefix)
		}
	}
	if !sources[c.DefaultSource] {
		return errors.New("discovery dns: default source must be in browse list")
	}
	for _, nameserver := range c.Nameservers {
		if !domain(nameserver) {
			return errors.New("discovery dns: invalid nameserver")
		}
		for delegated := range domains {
			if dns.IsSubDomain(delegated, nameserver) {
				return errors.New("discovery dns: nameserver must be outside all discovery zones")
			}
		}
	}
	return nil
}

// Load reads a bounded strict JSON configuration using the existing config loader.
func Load(path string) (Config, error) {
	var settings Config
	data, err := config.Read(path)
	if err != nil {
		return settings, err
	}
	if err := jsonwire.Decode(data, config.MaxBytes, &settings); err != nil {
		return settings, err
	}
	return settings, settings.Validate()
}
