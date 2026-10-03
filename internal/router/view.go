package router

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/publication"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

var errLANBudget = errors.New("LAN alias publication budget exceeded")

// views admits optional Services only when both deliveries fit their existing
// limits. A large optional snapshot cannot interrupt native device discovery.
func (c *collector) views(ctx context.Context, native []catalog.Record, links map[int]observation.Link, now catalog.Moment) ([]catalog.Record, []avahi.Intent, error) {
	records := native
	if optional := c.services.Records(now); len(optional) > 0 && len(native)+len(optional) <= catalog.MaxRecords {
		records = append(slices.Clone(native), optional...)
	}
	for {
		rendered := c.translator.Render(records, now)
		groups, err := lanGroups(ctx, rendered, c.identities, links, now)
		optional := len(records) > len(native)
		if optional && err == nil {
			// Reserve the largest revision field and a full generation ID.
			// Rendered addresses retain their native identity and short expiry.
			value := catalog.Snapshot{Schema: 2, Epoch: strings.Repeat("0", 32), Revision: math.MaxInt64, Issued: now.Wall, Until: now.Wall.Add(catalog.Lease), Records: rendered}
			data, encodeErr := json.Marshal(value)
			if encodeErr != nil {
				return nil, nil, encodeErr
			}
			if len(rendered) > catalog.MaxRecords || len(data) > catalog.MaxBytes {
				err = errLANBudget
			} else if _, frameErr := publication.Frame(strings.Repeat("0", 36), math.MaxInt64, now.Mono, groups); frameErr != nil {
				err = errLANBudget
			}
		}
		if optional && errors.Is(err, errLANBudget) {
			records = native
			continue
		}
		return records, groups, err
	}
}

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
		return nil, errLANBudget
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
