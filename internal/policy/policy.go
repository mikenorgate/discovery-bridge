// Package policy enforces configured discovery scopes and translation readiness.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// SourcePolicy contains immutable native source scopes and excluded networks.
type SourcePolicy struct {
	sources   map[string][]netip.Prefix
	forbidden []netip.Prefix
}

// New validates explicit operator scopes without adding installation defaults.
func New(sources map[string][]string, forbidden []string) (*SourcePolicy, error) {
	if len(sources) == 0 || len(sources) > 128 || len(forbidden) > 128 {
		return nil, errors.New("bounded explicit source policy required")
	}
	policy := &SourcePolicy{sources: make(map[string][]netip.Prefix)}
	parse := func(value string) (netip.Prefix, error) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("invalid discovery prefix: %q", value)
		}
		return prefix, nil
	}
	for name, values := range sources {
		if name == "" || len(values) == 0 || len(values) > 128 {
			return nil, errors.New("each source requires bounded prefixes")
		}
		for _, value := range values {
			prefix, err := parse(value)
			if err != nil {
				return nil, err
			}
			policy.sources[name] = append(policy.sources[name], prefix)
		}
	}
	for _, value := range forbidden {
		prefix, err := parse(value)
		if err != nil {
			return nil, err
		}
		policy.forbidden = append(policy.forbidden, prefix)
	}
	return policy, nil
}

// CheckAddress rejects addresses outside their observed source and unsafe scopes.
func (p *SourcePolicy) CheckAddress(source string, address netip.Addr) error {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return errors.New("unusable native discovery address")
	}
	for _, prefix := range p.forbidden {
		if prefix.Contains(address) {
			return errors.New("address belongs to an excluded scope")
		}
	}
	scopes := p.sources[source]
	matched := false
	for _, prefix := range scopes {
		if !prefix.Contains(address) {
			continue
		}
		matched = true
		if address.Is4() && prefix.Bits() < 31 {
			if address == prefix.Addr() {
				return errors.New("IPv4 network address is unusable")
			}
			a, network := address.As4(), prefix.Addr().As4()
			value := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
			base := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
			if value == base|(uint32(1)<<uint(32-prefix.Bits())-1) {
				return errors.New("IPv4 broadcast address is unusable")
			}
		}
	}
	if matched {
		return nil
	}
	return errors.New("address is outside its observed source scope")
}

// Sources returns copies of source scopes for configuration and feed selection.
func (p *SourcePolicy) Sources() map[string][]netip.Prefix {
	result := make(map[string][]netip.Prefix, len(p.sources))
	for name, prefixes := range p.sources {
		result[name] = slices.Clone(prefixes)
	}
	return result
}

// RemainingTTL floors the shortest validity deadline, with no freshness renewal.
func RemainingTTL(now time.Time, maximum uint32, deadlines ...time.Time) uint32 {
	if maximum == 0 || len(deadlines) == 0 {
		return 0
	}
	seconds := int64(maximum)
	for _, deadline := range deadlines {
		if !deadline.After(now) {
			return 0
		}
		remaining := int64(deadline.Sub(now) / time.Second)
		if remaining < seconds {
			seconds = remaining
		}
	}
	return uint32(seconds)
}

// Mapping is a sampled installed NAT46 mapping, never an allocation request.
type Mapping struct {
	EndpointID             string
	Target                 netip.Addr
	Alias                  netip.Addr
	DesiredGeneration      uint64
	InstalledGeneration    uint64
	AcknowledgedGeneration uint64
	State                  string
	ValidUntil             time.Time
}

// Ready permits an alias only for an exact ready, unexpired installed mapping.
func (m Mapping) Ready(endpoint string, target netip.Addr, pool netip.Prefix, reserved []netip.Addr, now time.Time) bool {
	if m.EndpointID != endpoint || m.Target != target || !target.Is6() || target.Is4In6() || target.Zone() != "" || target.IsLoopback() || target.IsLinkLocalUnicast() || target.IsMulticast() || target.IsUnspecified() || !m.Alias.Is4() || !pool.IsValid() || !pool.Addr().Is4() || pool.Bits() > 30 || m.State != "ready" || m.DesiredGeneration == 0 || m.DesiredGeneration != m.InstalledGeneration || m.DesiredGeneration != m.AcknowledgedGeneration || !m.ValidUntil.After(now) || !pool.Contains(m.Alias) || slices.Contains(reserved, m.Alias) {
		return false
	}
	policy, err := New(map[string][]string{"alias": {pool.String()}}, nil)
	return err == nil && policy.CheckAddress("alias", m.Alias) == nil
}

// NAT64 synthesizes only from an explicitly configured /96 prefix.
func NAT64(prefix netip.Prefix, address netip.Addr) (netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != 96 || prefix != prefix.Masked() || !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return netip.Addr{}, errors.New("valid IPv6 /96 and usable IPv4 address required")
	}
	if prefix == netip.MustParsePrefix("64:ff9b::/96") && !address.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("well-known prefix requires a global IPv4 address")
	}
	// RFC6052 excludes RFC1918 from the well-known translation prefix.
	if prefix == netip.MustParsePrefix("64:ff9b::/96") && address.IsPrivate() {
		return netip.Addr{}, errors.New("well-known prefix cannot translate private IPv4")
	}
	result := prefix.Addr().As16()
	v4 := address.As4()
	copy(result[12:], v4[:])
	return netip.AddrFrom16(result), nil
}
