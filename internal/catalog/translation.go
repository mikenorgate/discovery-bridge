package catalog

import (
	"net/netip"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

// Translate derives addresses only from explicit readiness samples and mappings.
// It has no allocation callback; native addresses always take precedence.
func Translate(records []Record, now time.Time, until time.Time, t Translation, mappings map[string]policy.Mapping, nat64Ready, nat46Ready bool) []Record {
	result := make([]Record, 0, len(records))
	hosts := make(map[string]map[string]bool)
	for _, r := range records {
		if r.NativeID != "" || !r.Expires.After(now) {
			continue
		}
		result = append(result, r)
		key := r.Source + "\x00" + NameKey(r.Name)
		if hosts[key] == nil {
			hosts[key] = make(map[string]bool)
		}
		hosts[key][r.Type] = true
	}
	native := len(result)
	for index := 0; index < native && len(result) < MaxRecords; index++ {
		r := result[index]
		types := hosts[r.Source+"\x00"+NameKey(r.Name)]
		target, err := netip.ParseAddr(r.Data)
		if err != nil {
			continue
		}
		derived := r
		derived.NativeID = r.ID
		derived.Expires = minTime(r.Expires, until)
		if nat64Ready && until.After(now) && r.Type == "A" && !types["AAAA"] && !t.Pool.Contains(target) {
			address, err := policy.NAT64(t.NAT64, target)
			if err == nil {
				derived.ID = r.ID + ":nat64"
				derived.Type = "AAAA"
				derived.Data = address.String()
				result = append(result, derived)
			}
		}
		if nat46Ready && r.Type == "AAAA" && !types["A"] {
			mapping := mappings[r.ID]
			if mapping.Ready(r.ID, target, t.Pool, t.Reserved, now) {
				ttl := policy.RemainingTTL(now, MaxTTL, r.Expires, until, mapping.ValidUntil)
				if ttl > 0 {
					derived.ID = r.ID + ":nat46"
					derived.Type = "A"
					derived.Data = mapping.Alias.String()
					derived.Expires = now.Add(time.Duration(ttl) * time.Second)
					result = append(result, derived)
				}
			}
		}
	}
	return result
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
