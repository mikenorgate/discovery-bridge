package config

import (
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Translator identifies an operator-installed immutable TAYGA profile.
type Translator struct {
	Interface     string `json:"interface"`
	Unit          string `json:"unit"`
	Config        string `json:"config"`
	Binary        string `json:"binary"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	Prefix        string `json:"prefix"`
	DataDirectory string `json:"data_directory"`
	DynamicPool   string `json:"dynamic_pool,omitempty"`
}

// Translators configures a read-only collector sampler, never allocation.
type Translators struct {
	Translation
	IP        []string    `json:"ip"`
	Systemctl []string    `json:"systemctl"`
	NAT46     *Translator `json:"nat46,omitempty"`
	NAT64     *Translator `json:"nat64,omitempty"`
}

var serviceUnit = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+\.service$`)

func normalizedPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\n")
}

// Validate binds readiness to explicit local profiles and translation spaces.
func (t *Translators) Validate() error {
	if t == nil {
		return nil
	}
	spaces, err := t.Parse()
	if err != nil {
		return err
	}
	if !Command(t.IP) || !Command(t.Systemctl) || t.NAT46 == nil && t.NAT64 == nil {
		return errors.New("explicit translator profiles and read-only commands required")
	}
	for _, profile := range []*Translator{t.NAT46, t.NAT64} {
		if profile == nil {
			continue
		}
		v4, err4 := netip.ParseAddr(profile.IPv4)
		v6, err6 := netip.ParseAddr(profile.IPv6)
		prefix, err := netip.ParsePrefix(profile.Prefix)
		if len(profile.Interface) < 1 || len(profile.Interface) > 15 || strings.ContainsAny(profile.Interface, "/\x00\n ") || !serviceUnit.MatchString(profile.Unit) || len(profile.Unit) > 255 || !normalizedPath(profile.Config) || !normalizedPath(profile.Binary) || !normalizedPath(profile.DataDirectory) || err4 != nil || !v4.Is4() || !v4.IsGlobalUnicast() || v4.IsLinkLocalUnicast() || err6 != nil || !v6.Is6() || v6.Is4In6() || v6.Zone() != "" || !v6.IsGlobalUnicast() || v6.IsLinkLocalUnicast() || err != nil || prefix != prefix.Masked() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != 96 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLinkLocalUnicast() {
			return errors.New("invalid immutable translator profile")
		}
		if profile == t.NAT46 {
			if profile.DynamicPool != "" || prefix == spaces.NAT64 || spaces.Pool.Contains(v4) && !slices.Contains(spaces.Reserved, v4) {
				return errors.New("NAT46 requires a distinct prefix and reserved TUN address")
			}
		} else {
			pool, err := netip.ParsePrefix(profile.DynamicPool)
			if prefix != spaces.NAT64 || err != nil || !pool.Addr().Is4() || pool != pool.Masked() || pool.Bits() < 8 || pool.Bits() > 30 || !pool.Addr().IsGlobalUnicast() || pool.Addr().IsLinkLocalUnicast() || pool.Overlaps(spaces.Pool) {
				return errors.New("invalid NAT64 dynamic pool or prefix")
			}
		}
	}
	if t.NAT46 != nil && t.NAT64 != nil && (t.NAT46.Interface == t.NAT64.Interface || t.NAT46.Unit == t.NAT64.Unit || t.NAT46.Config == t.NAT64.Config) {
		return errors.New("distinct translator instances required")
	}
	return nil
}
