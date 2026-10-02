// Package publication admits leased snapshots from one local collector UID.
package publication

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

// MaxFrame retains the existing local producer byte bound.
const MaxFrame = 1_048_576

type wireRecord struct {
	Name   *string `json:"name"`
	Type   *uint16 `json:"type"`
	Data   *string `json:"data"`
	Source *string `json:"source"`
	Unique *bool   `json:"unique"`
}

type wireGroup struct {
	Interface *int          `json:"interface"`
	Family    *int          `json:"family"`
	Deadline  *float64      `json:"deadline"`
	Records   *[]wireRecord `json:"records"`
}

type wireFrame struct {
	Boot     *string      `json:"boot"`
	Sequence *int64       `json:"sequence"`
	Issued   *float64     `json:"issued"`
	Groups   *[]wireGroup `json:"groups"`
}

// Admission binds publication to configured links and persistent SQLite ownership.
type Admission struct {
	Boot     string
	Links    map[int]observation.Link
	Sources  map[string]bool
	Owns     func(string) (bool, error)
	OwnsHost func(string, string) (bool, error)
}

// Decode validates the complete envelope and graph before any advertisement changes.
func (a Admission) Decode(payload []byte, now time.Duration, previous int64) (int64, []avahi.Intent, error) {
	var value wireFrame
	if err := jsonwire.Decode(payload, MaxFrame, &value); err != nil {
		return 0, nil, err
	}
	if a.Boot == "" || a.Owns == nil || len(a.Links) == 0 || now < 0 || value.Boot == nil || *value.Boot != a.Boot || value.Sequence == nil || *value.Sequence <= previous || *value.Sequence == math.MaxInt64 || value.Issued == nil || value.Groups == nil || len(*value.Groups) > 12 {
		return 0, nil, errors.New("invalid local publication envelope or replay")
	}
	issued, nowSeconds := *value.Issued, now.Seconds()
	if math.IsNaN(issued) || math.IsInf(issued, 0) || issued < 0 || nowSeconds-issued < 0 || nowSeconds-issued > 1 {
		return 0, nil, errors.New("stale publication snapshot")
	}
	var intents []avahi.Intent
	keys := make(map[[2]int]bool)
	budget := 0
	for _, group := range *value.Groups {
		if group.Interface == nil || group.Family == nil || group.Deadline == nil || group.Records == nil {
			return 0, nil, errors.New("incomplete publication group")
		}
		index, family, deadline := *group.Interface, *group.Family, *group.Deadline
		link, ok := a.Links[index]
		key := [2]int{index, family}
		if !ok || !slices.Contains(link.Families, family) || keys[key] || math.IsNaN(deadline) || math.IsInf(deadline, 0) || deadline <= nowSeconds || deadline > issued+30 {
			return 0, nil, errors.New("invalid publication link or lease")
		}
		keys[key] = true
		budget += len(*group.Records)
		if budget > catalog.MaxRecords {
			return 0, nil, errors.New("publication record limit")
		}
		records := make([]catalog.TimedRecord, 0, len(*group.Records))
		authority := catalog.Authority{IDs: make(map[string]bool), Unique: make(map[catalog.RRSet]bool)}
		for i, record := range *group.Records {
			if record.Name == nil || record.Type == nil || record.Data == nil || record.Source == nil || record.Unique == nil || !observation.Supported(*record.Type) || !catalog.LocalName(*record.Name) || len(*record.Data) > 16384 {
				return 0, nil, errors.New("invalid publication record")
			}
			name, kind, data, source, unique := *record.Name, *record.Type, *record.Data, *record.Source, *record.Unique
			approvedSource := a.Sources[source]
			for _, candidate := range a.Links {
				approvedSource = approvedSource || candidate.Source == source
			}
			if !approvedSource {
				return 0, nil, errors.New("unapproved publication source")
			}
			value := catalog.Record{ID: fmt.Sprint(i), Name: name, Type: dns.TypeToString[kind], Data: data, Source: source}
			rr, err := value.RR(1)
			if err != nil {
				return 0, nil, err
			}
			if kind == dns.TypePTR && unique {
				return 0, nil, errors.New("browse PTR must be shared")
			}
			if kind != dns.TypePTR {
				owned, err := a.Owns(name)
				if err != nil {
					return 0, nil, err
				}
				if !owned && (kind == dns.TypeA || kind == dns.TypeAAAA) && source != link.Source && a.OwnsHost != nil {
					owned, err = a.OwnsHost(source, name)
					if err != nil {
						return 0, nil, err
					}
				}
				if !unique || !owned {
					return 0, nil, errors.New("unique name lacks persistent publication ownership")
				}
			}
			switch rr := rr.(type) {
			case *dns.PTR:
				if !catalog.LocalName(rr.Ptr) {
					return 0, nil, errors.New("foreign publication PTR dependency")
				}
			case *dns.SRV:
				if !catalog.LocalName(rr.Target) {
					return 0, nil, errors.New("foreign publication SRV dependency")
				}
			}
			authority.IDs[value.ID] = true
			if unique {
				authority.Unique[(catalog.Answer{RR: rr}).Set()] = true
			}
			records = append(records, catalog.TimedRecord{Record: value, TTL: 1})
		}
		view := catalog.ResponseView(records, authority)
		if len(view) != len(records) {
			return 0, nil, errors.New("incomplete, duplicate or colliding publication graph")
		}
		intents = append(intents, avahi.Intent{Interface: index, Family: family, Deadline: time.Duration(deadline * float64(time.Second)), Records: view})
	}
	return *value.Sequence, intents, nil
}

// Frame encodes the existing newline-delimited local producer protocol.
func Frame(boot string, sequence int64, now time.Duration, intents []avahi.Intent) ([]byte, error) {
	issued := now.Seconds()
	groups := make([]wireGroup, 0, len(intents))
	for _, intent := range intents {
		deadline, index, family := intent.Deadline.Seconds(), intent.Interface, intent.Family
		records := make([]wireRecord, 0, len(intent.Records))
		for _, answer := range intent.Records {
			if answer.RR == nil {
				return nil, errors.New("nil publication answer")
			}
			rr := answer.RR
			name, kind := rr.Header().Name, rr.Header().Rrtype
			data, source, unique := strings.TrimPrefix(rr.String(), rr.Header().String()), answer.Source, answer.Unique
			records = append(records, wireRecord{&name, &kind, &data, &source, &unique})
		}
		groups = append(groups, wireGroup{&index, &family, &deadline, &records})
	}
	value := wireFrame{&boot, &sequence, &issued, &groups}
	payload, err := json.Marshal(value)
	if err != nil || len(payload)+1 > MaxFrame {
		return nil, errors.New("local publication frame exceeds byte budget")
	}
	return append(payload, '\n'), nil
}
