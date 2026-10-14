package discoverydns

import (
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

// dependencyTTLs bounds aliases, service targets and browse pointers by the
// shortest supporting lifetime. The input is an owned, harmonized snapshot.
func dependencyTTLs(records []dns.RR) []dns.RR {
	hosts, services := make(map[string]uint32), make(map[string]uint32)
	shorten := func(lifetimes map[string]uint32, name string, ttl uint32) {
		key := catalog.NameKey(name)
		if old, exists := lifetimes[key]; !exists || ttl < old {
			lifetimes[key] = ttl
		}
	}
	for _, record := range records {
		if kind := record.Header().Rrtype; kind == dns.TypeA || kind == dns.TypeAAAA {
			shorten(hosts, record.Header().Name, record.Header().Ttl)
		}
	}
	for range 8 {
		for _, record := range records {
			if alias, ok := record.(*dns.CNAME); ok {
				if ttl, exists := hosts[catalog.NameKey(alias.Target)]; exists {
					alias.Hdr.Ttl = min(alias.Hdr.Ttl, ttl)
					shorten(hosts, alias.Hdr.Name, alias.Hdr.Ttl)
				}
			}
		}
	}
	for _, record := range records {
		if service, ok := record.(*dns.SRV); ok {
			if ttl, exists := hosts[catalog.NameKey(service.Target)]; exists {
				service.Hdr.Ttl = min(service.Hdr.Ttl, ttl)
			}
			shorten(services, service.Hdr.Name, service.Hdr.Ttl)
		}
	}
	for _, record := range records {
		if pointer, ok := record.(*dns.PTR); ok {
			if ttl, exists := services[catalog.NameKey(pointer.Ptr)]; exists {
				pointer.Hdr.Ttl = min(pointer.Hdr.Ttl, ttl)
			}
		}
	}
	return records
}
