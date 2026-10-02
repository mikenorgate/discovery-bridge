package avahi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

func localName(name string) (string, error) {
	name = dns.Fqdn(name)
	if !catalog.LocalName(name) {
		return "", errors.New("avahi names must be within .local")
	}
	return catalog.NameKey(name), nil
}

// avahiName preserves raw label bytes using Avahi's decimal presentation escapes.
// It does not apply IDNA or the zone-file escapes used by the DNS library.
func avahiName(name string) (string, error) {
	if !catalog.LocalName(dns.Fqdn(name)) {
		return "", errors.New("avahi names must be within .local")
	}
	wire := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), wire, 0, nil, false)
	if err != nil {
		return "", err
	}
	var result strings.Builder
	for i := 0; i < n && wire[i] != 0; {
		length := int(wire[i])
		i++
		for end := i + length; i < end; i++ {
			value := wire[i]
			if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '-' {
				result.WriteByte(value)
			} else {
				fmt.Fprintf(&result, `\%03d`, value)
			}
		}
		result.WriteByte('.')
	}
	return result.String(), nil
}

// rdata returns uncompressed DNS wire RDATA for Avahi's AddRecord method.
func rdata(rr dns.RR) ([]byte, error) {
	// PackRR updates Rdlength; retain callers' immutable catalog records.
	rr = dns.Copy(rr)
	wire := make([]byte, dns.Len(rr)+256)
	n, err := dns.PackRR(rr, wire, 0, nil, false)
	if err != nil {
		return nil, err
	}
	_, next, err := dns.UnpackDomainName(wire[:n], 0)
	if err != nil || next+10 > n {
		return nil, errors.New("invalid Avahi record framing")
	}
	return wire[next+10 : n], nil
}

func rawRecord(name string, kind uint16, raw []byte) (dns.RR, error) {
	if !observation.Supported(kind) || len(raw) > 4096 || !catalog.LocalName(name) {
		return nil, errors.New("invalid Avahi record name, type or data size")
	}
	wire := make([]byte, 256+10+len(raw))
	n, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(wire[n:n+2], kind)
	binary.BigEndian.PutUint16(wire[n+2:n+4], dns.ClassINET)
	binary.BigEndian.PutUint16(wire[n+8:n+10], uint16(len(raw)))
	copy(wire[n+10:], raw)
	rr, end, err := dns.UnpackRR(wire[:n+10+len(raw)], 0)
	if err != nil || end != n+10+len(raw) {
		return nil, errors.New("invalid Avahi wire record")
	}
	packed, err := rdata(rr)
	if err != nil || !bytes.Equal(packed, raw) {
		return nil, errors.New("avahi RDATA must be complete and uncompressed")
	}
	switch value := rr.(type) {
	case *dns.PTR:
		if !catalog.LocalName(value.Ptr) {
			return nil, errors.New("foreign Avahi PTR target")
		}
	case *dns.SRV:
		if !catalog.LocalName(value.Target) {
			return nil, errors.New("foreign Avahi SRV target")
		}
	}
	return rr, nil
}
