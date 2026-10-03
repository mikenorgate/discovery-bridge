package translation

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

const lease = 10 * time.Second

type readiness struct {
	observed   catalog.Moment
	nat64      bool
	maps       map[netip.Addr]netip.Addr
	generation uint64
}

// Sampler shares one bounded local observation with LAN and pod renderers.
// Stored samples are immutable, including their maps, and never renew on reads.
type Sampler struct {
	settings config.Translators
	spaces   catalog.Translation
	lans     map[string]bool
	observer observer
	current  atomic.Pointer[readiness]
}

// New validates and copies all operator authority. No settings means disabled.
func New(settings *config.Translators, lans []config.LAN) (*Sampler, error) {
	if settings == nil {
		return nil, nil
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	spaces, err := settings.Parse()
	if err != nil {
		return nil, err
	}
	copy := *settings
	copy.Reserved, copy.IP, copy.Systemctl = slices.Clone(settings.Reserved), slices.Clone(settings.IP), slices.Clone(settings.Systemctl)
	if copy.NAT46 != nil {
		profile := *copy.NAT46
		copy.NAT46 = &profile
	}
	if copy.NAT64 != nil {
		profile := *copy.NAT64
		copy.NAT64 = &profile
	}
	s := &Sampler{settings: copy, spaces: *spaces, lans: make(map[string]bool), observer: localObserver()}
	for _, lan := range lans {
		s.lans[lan.Interface] = true
	}
	return s, nil
}

// Run polls every two seconds after the preceding bounded sample completes.
// The caller owns the single goroutine and joins it before closing resources.
func (s *Sampler) Run(ctx context.Context) {
	if s == nil {
		return
	}
	defer s.current.Store(nil)
	for ctx.Err() == nil {
		value := s.observer.observe(ctx, s.settings, s.spaces, s.lans)
		s.current.Store(&value)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Render preserves native records when observation is missing, stale or subject
// to a clock discontinuity. NAT46 uses only maps already loaded by the instance.
func (s *Sampler) Render(records []catalog.Record, now catalog.Moment) []catalog.Record {
	if s == nil {
		return records
	}
	value := s.current.Load()
	if value == nil {
		return records
	}
	elapsed := now.Mono - value.observed.Mono
	difference := now.Wall.Sub(value.observed.Wall) - elapsed
	if elapsed < 0 || elapsed >= lease || difference < -2*time.Second || difference > 2*time.Second {
		return records
	}
	until := value.observed.Wall.Add(lease)
	if monotonicUntil := now.Wall.Add(lease - elapsed); monotonicUntil.Before(until) {
		until = monotonicUntil
	}
	mappings := make(map[string]policy.Mapping)
	for _, r := range records {
		if r.Type != "AAAA" || r.NativeID != "" {
			continue
		}
		target, err := netip.ParseAddr(r.Data)
		if err != nil {
			continue
		}
		if alias, ok := value.maps[target]; ok {
			mappings[r.ID] = policy.Mapping{EndpointID: r.ID, Target: target, Alias: alias, DesiredGeneration: value.generation, InstalledGeneration: value.generation, AcknowledgedGeneration: value.generation, State: "ready", ValidUntil: until}
		}
	}
	return catalog.Translate(records, now.Wall, until, s.spaces, mappings, value.nat64, true)
}
