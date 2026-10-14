package discoverydns

import (
	"encoding/base32"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
)

// successor returns the next legal DNS name in canonical order. Most names
// admit a zero-octet child; full-length names instead increment their leftmost
// label, carrying toward the root only when no label successor exists.
func successor(name string) string {
	name = catalog.NameKey(name)
	if next := "\\000." + name; dnswire.Name(next) {
		return next
	}
	wire := make([]byte, 255)
	end, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return ""
	}
	for offset := 0; offset < end && wire[offset] != 0; {
		length := int(wire[offset])
		for index := offset + length; index > offset; index-- {
			if wire[index] == 255 {
				continue
			}
			wire[index]++
			next := append([]byte{byte(index - offset)}, wire[offset+1:index+1]...)
			next = append(next, wire[offset+length+1:end]...)
			result, _, err := dns.UnpackDomainName(next, 0)
			if err == nil {
				return result
			}
			return ""
		}
		offset += length + 1
	}
	return ""
}

func narrowNSEC3(name, zone string, types []uint16) dns.RR {
	hash := dns.HashName(name, dns.SHA1, 0, "")
	if !dnswire.Name(hash + "." + zone) {
		return nil
	}
	// SHA-1 is required here by the DNSSEC wire format, not used for authentication.
	encoding := base32.HexEncoding.WithPadding(base32.NoPadding)
	bytes, err := encoding.DecodeString(hash)
	if err != nil || len(bytes) != 20 {
		return nil
	}
	for index := len(bytes) - 1; index >= 0; index-- {
		bytes[index]++
		if bytes[index] != 0 {
			break
		}
	}
	return &dns.NSEC3{
		Hdr:  dns.RR_Header{Name: hash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 10},
		Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", SaltLength: 0, HashLength: 20,
		NextDomain: encoding.EncodeToString(bytes), TypeBitMap: types,
	}
}
