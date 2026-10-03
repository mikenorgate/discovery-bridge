package router

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

// podView preserves coherent original names as shared answers. The bridge has
// not probed ownership inside the pod and never advertises the pod itself.
func podView(records []catalog.Record, now time.Time) []catalog.Answer {
	authority := catalog.Authority{IDs: make(map[string]bool)}
	values := make([]catalog.TimedRecord, 0, len(records))
	for _, record := range records {
		if ttl := min(record.Expires.Sub(now)/time.Second, catalog.MaxTTL); ttl > 0 {
			authority.IDs[record.ID] = true
			values = append(values, catalog.TimedRecord{Record: record, TTL: uint32(ttl)})
		}
	}
	return catalog.ResponseView(values, authority)
}

// lanGroups reserves the reconciliation and frame-age budgets before compiling
// dependencies. Original hostnames appear only on links other than their origin.
func lanGroups(ctx context.Context, records []catalog.Record, identities *state.Identities, links map[int]observation.Link, now catalog.Moment) ([]avahi.Intent, error) {
	live := make([]catalog.Record, 0, len(records))
	for _, record := range records {
		if record.Expires.Sub(now.Wall) >= 5*time.Second {
			live = append(live, record)
		}
	}
	aliases, err := identities.Compile(ctx, live, now.Wall)
	if err != nil {
		return nil, err
	}
	var hosts []catalog.Answer
	suppressed := identities.SuppressedHosts()
	for _, answer := range podView(live, now.Wall) {
		kind := answer.RR.Header().Rrtype
		if kind != dns.TypeA && kind != dns.TypeAAAA || suppressed[catalog.NameKey(answer.RR.Header().Name)] {
			continue
		}
		owned, err := identities.OwnsHost(ctx, answer.Source, answer.RR.Header().Name)
		if err != nil {
			return nil, err
		}
		if owned {
			answer.Unique = true
			hosts = append(hosts, answer)
		}
	}
	groups := make(map[int][]catalog.Answer)
	budget, base := 0, 0
	for index, link := range links {
		values := slices.Clone(aliases)
		for _, host := range hosts {
			if host.Source != link.Source {
				values = append(values, host)
			}
		}
		groups[index] = values
		budget += len(values) * len(link.Families)
		base += len(aliases) * len(link.Families)
	}
	if base > catalog.MaxRecords {
		return nil, errors.New("LAN alias publication budget exceeded")
	}
	var intents []avahi.Intent
	for index, link := range links {
		values := groups[index]
		if budget > catalog.MaxRecords {
			values = aliases // Original hosts are optional; aliases retain the budget.
		}
		if len(values) == 0 {
			continue
		}
		ttl := uint32(catalog.MaxTTL)
		for _, value := range values {
			ttl = min(ttl, value.RR.Header().Ttl)
		}
		for _, family := range link.Families {
			intents = append(intents, avahi.Intent{Interface: index, Family: family, Deadline: now.Mono + time.Duration(ttl)*time.Second, Records: values})
		}
	}
	slices.SortFunc(intents, func(a, b avahi.Intent) int {
		if a.Interface != b.Interface {
			return a.Interface - b.Interface
		}
		return a.Family - b.Family
	})
	return intents, nil
}
