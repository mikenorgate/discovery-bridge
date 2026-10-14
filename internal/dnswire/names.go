package dnswire

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Name validates an absolute DNS name without interpreting its label bytes.
func Name(name string) bool {
	if !dns.IsFqdn(name) || len(name) > 1024 {
		return false
	}
	wire := make([]byte, 255)
	_, err := dns.PackDomainName(name, wire, 0, nil, false)
	return err == nil
}

// ReverseIP accepts only complete IPv4 or IPv6 reverse-mapping owner names.
func ReverseIP(name string) (netip.Addr, error) {
	labels := dns.SplitDomainName(dns.CanonicalName(name))
	if len(labels) == 6 && labels[4] == "in-addr" && labels[5] == "arpa" {
		return netip.ParseAddr(strings.Join([]string{labels[3], labels[2], labels[1], labels[0]}, "."))
	}
	if len(labels) == 34 && labels[32] == "ip6" && labels[33] == "arpa" {
		var digits strings.Builder
		for index := 31; index >= 0; index-- {
			if len(labels[index]) != 1 {
				return netip.Addr{}, errors.New("invalid reverse nibble")
			}
			digits.WriteString(labels[index])
		}
		value, err := hex.DecodeString(digits.String())
		if err == nil {
			address, ok := netip.AddrFromSlice(value)
			if ok {
				return address, nil
			}
		}
	}
	return netip.Addr{}, errors.New("complete reverse owner required")
}

// ReverseZone returns the DNS delegation for an octet- or nibble-aligned prefix.
func ReverseZone(prefix netip.Prefix) (string, error) {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
		return "", errors.New("explicit masked reverse prefix required")
	}
	width, labels := 4, 32
	if prefix.Addr().Is4() {
		width, labels = 8, 4
	}
	if prefix.Bits()%width != 0 {
		return "", errors.New("reverse prefix must be octet or nibble aligned")
	}
	name, err := dns.ReverseAddr(prefix.Addr().String())
	if err != nil {
		return "", err
	}
	return strings.Join(dns.SplitDomainName(name)[labels-prefix.Bits()/width:], ".") + ".", nil
}

// LocalOrReverse admits native questions only on an explicitly configured link.
func LocalOrReverse(name string, prefixes []netip.Prefix) bool {
	if !Name(name) {
		return false
	}
	if dns.IsSubDomain("local.", name) {
		return true
	}
	address, err := ReverseIP(name)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
