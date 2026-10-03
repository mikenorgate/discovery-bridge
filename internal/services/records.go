// Package services publishes explicitly selected, ready LoadBalancer Services
// through the existing collector and independent LAN ownership process.
package services

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/registry"
)

const Lease = 15 * time.Second

// Intent retains the existing producer wire format. Addresses are admitted VIPs.
type Intent struct {
	config.Service
	UID         string   `json:"uid"`
	Addresses   []string `json:"addresses"`
	ServicePort int      `json:"service_port"`
}

// Snapshot is an absolute, full Service intent replacement.
type Snapshot struct {
	Schema   int       `json:"schema"`
	Issued   time.Time `json:"issued_at"`
	Until    time.Time `json:"valid_until"`
	Services []Intent  `json:"services"`
}

var serviceUID = regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`)

func labelName(label, domain string) (string, error) {
	var wire [256]byte
	n, err := dns.PackDomainName(domain, wire[:], len(label)+1, nil, false)
	if err != nil || len(label) > 63 {
		return "", errors.New("service instance label limit")
	}
	wire[0] = byte(len(label))
	copy(wire[1:], label)
	name, _, err := dns.UnpackDomainName(wire[:n], 0)
	return name, err
}

// Records validates metadata and VIPs again at the collector admission boundary.
func Records(intents []Intent, until time.Time, source string, scopes *policy.SourcePolicy) ([]catalog.Record, error) {
	if intents == nil || len(intents) > config.MaxServices || source == "" || scopes == nil {
		return nil, errors.New("bounded Service intent and VIP authority required")
	}
	result := make([]catalog.Record, 0)
	seen, records := make(map[[3]string]bool), make(map[string]bool)
	for _, intent := range intents {
		if err := intent.Validate(); err != nil {
			return nil, err
		}
		if seen[intent.Key()] || !serviceUID.MatchString(intent.UID) || intent.ServicePort < 1 || intent.ServicePort > 65535 || len(intent.Addresses) < 1 || len(intent.Addresses) > 4 {
			return nil, errors.New("invalid or duplicate external Service intent")
		}
		seen[intent.Key()] = true
		addresses := make(map[netip.Addr]bool)
		for _, raw := range intent.Addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || scopes.CheckAddress(source, address) != nil || addresses[address] {
				return nil, errors.New("invalid, duplicate or unapproved LoadBalancer VIP")
			}
			addresses[address] = true
		}
		key := intent.Key()
		data, err := jsonwire.Encode([]string{key[0], key[1], key[2], intent.UID})
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		identity := hex.EncodeToString(hash[:])[:12]
		host := "kube-" + identity + ".local."
		kind, err := registry.ObservedType(intent.Type)
		if err != nil {
			return nil, err
		}
		domain := kind + ".local."
		instance, err := labelName(intent.Instance+"-"+identity[:8], domain)
		if err != nil {
			return nil, err
		}
		header := func(name string, kind uint16) dns.RR_Header {
			return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET}
		}
		entries := []dns.RR{
			&dns.PTR{Hdr: header(catalog.Enumeration, dns.TypePTR), Ptr: domain},
			&dns.PTR{Hdr: header(domain, dns.TypePTR), Ptr: instance},
			&dns.SRV{Hdr: header(instance, dns.TypeSRV), Port: uint16(intent.ServicePort), Target: host},
		}
		keys := make([]string, 0, len(intent.TXT))
		for key := range intent.TXT {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		fields := make([]string, 0, len(keys))
		for _, key := range keys {
			// Configuration contains literal bytes; miekg/dns expects escaped
			// presentation strings. Preserve backslashes, including \DDD text.
			fields = append(fields, strings.ReplaceAll(key+"="+intent.TXT[key], `\`, `\\`))
		}
		if len(fields) == 0 {
			fields = []string{""}
		}
		entries = append(entries, &dns.TXT{Hdr: header(instance, dns.TypeTXT), Txt: fields})
		for _, raw := range intent.Addresses {
			address := netip.MustParseAddr(raw)
			if address.Is4() {
				a := address.As4()
				entries = append(entries, &dns.A{Hdr: header(host, dns.TypeA), A: a[:]})
			} else {
				a := address.As16()
				entries = append(entries, &dns.AAAA{Hdr: header(host, dns.TypeAAAA), AAAA: a[:]})
			}
		}
		for _, subtype := range intent.Subtypes {
			entries = append(entries, &dns.PTR{Hdr: header("_"+subtype+"._sub."+domain, dns.TypePTR), Ptr: instance})
		}
		for _, rr := range entries {
			h := rr.Header()
			data := strings.TrimPrefix(rr.String(), h.String())
			encoded, err := jsonwire.Encode([]any{source, h.Name, h.Rrtype, data})
			if err != nil {
				return nil, err
			}
			hash := sha256.Sum256(encoded)
			id := hex.EncodeToString(hash[:])
			if !records[id] {
				records[id] = true
				result = append(result, catalog.Record{ID: id, Name: h.Name, Type: dns.TypeToString[h.Rrtype], Data: data, Source: source, Expires: until})
			}
		}
	}
	return result, nil
}
