package router

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/publication"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
	"github.com/mikenorgate/discovery-bridge/internal/services"
	"github.com/mikenorgate/discovery-bridge/internal/state"
	"github.com/mikenorgate/discovery-bridge/internal/translation"
)

type demand struct {
	ctx      context.Context // The bounded request context, never a process lifetime.
	question responder.Question
	reply    chan error
}

type collectorEpoch struct {
	done     <-chan struct{}
	requests chan demand
}

// collector serializes observation mutation in the epoch's main loop. The gate
// makes failure withdrawal atomic with the last successful feed publication.
type collector struct {
	mu         sync.Mutex
	current    *collectorEpoch
	feed       *gateway.Feed
	identities *state.Identities
	settings   config.Router
	translator *translation.Sampler
	services   *services.Receiver
}

func (c *collector) demand(ctx context.Context, question responder.Question) error {
	c.mu.Lock()
	epoch := c.current
	c.mu.Unlock()
	if epoch == nil {
		return errors.New("LAN collector unavailable")
	}
	request := demand{ctx: ctx, question: question, reply: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-epoch.done:
		return errors.New("LAN observation epoch changed")
	case epoch.requests <- request:
	default:
		return gateway.ErrBusy
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-epoch.done:
		return errors.New("LAN observation epoch changed")
	case err := <-request.reply:
		return err
	}
}

func (c *collector) withdraw(epoch *collectorEpoch) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == epoch {
		c.current = nil
	}
	if c.feed != nil {
		c.feed.Withdraw()
	}
}

// browseDemand converts only admitted names and record types into new LAN
// questions. Original packets and LAN questions never enter a pod namespace.
func (c *collector) browseDemand(ctx context.Context, b *avahi.Browser, t *topology, question responder.Question) error {
	source, name, err := c.identities.Original(ctx, question.Name)
	if errors.Is(err, sql.ErrNoRows) {
		owned, err := c.identities.Owns(ctx, question.Name)
		if err != nil {
			return err
		}
		if owned {
			return nil // Retired aliases cannot query the bridge's own publications.
		}
		name, source = question.Name, ""
	} else if err != nil {
		return err
	}
	kinds := []uint16{question.Type}
	if question.Type == dns.TypeANY {
		kinds = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypePTR, dns.TypeSRV, dns.TypeTXT}
	} else if c.translator != nil && (question.Type == dns.TypeA || question.Type == dns.TypeAAAA) {
		kinds = []uint16{dns.TypeA, dns.TypeAAAA}
	}
	for index, link := range t.links {
		if source != "" && source != link.Source {
			continue
		}
		for _, family := range link.Families {
			for _, kind := range kinds {
				if _, err := b.Watch(ctx, avahi.Query{Interface: index, Family: family, Name: name, Type: kind}); err != nil {
					return err
				}
			}
			if err := b.Err(); err != nil {
				return err
			}
			if err := t.senders[socketKey{index, family}].Questions(ctx, name, kinds); err != nil {
				return err
			}
		}
	}
	return b.Err()
}

type observationEvent struct {
	hint     avahi.Event
	wire     []observation.Record
	now      catalog.Moment
	rejected string
}

func (c *collector) collect(ctx context.Context, boot string, log *json.Encoder) (err error) {
	stop, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	epoch := &collectorEpoch{done: stop.Done(), requests: make(chan demand, 64)}
	withdrawn := make(chan struct{})
	withdraw := context.AfterFunc(stop, func() { c.withdraw(epoch); close(withdrawn) })
	defer func() {
		cancel(nil)
		if withdraw() {
			c.withdraw(epoch)
		} else {
			<-withdrawn
		}
	}()
	monitor, err := observation.OpenMonitor()
	if err != nil {
		return err
	}
	defer func() { _ = monitor.Close() }()
	t, err := capture(c.settings, true)
	if err != nil {
		return err
	}
	defer func() { _ = t.close() }()
	browser, err := avahi.ConnectBrowser(stop, c.settings.BusSocket, t.links)
	if err != nil {
		return err
	}
	defer browser.Close()
	producer, err := publication.Dial(stop, c.settings.PublisherSocket, boot)
	if err != nil {
		return err
	}
	defer func() { _ = producer.Close() }()
	events := make(chan observationEvent, 64)
	var workers sync.WaitGroup
	defer func() {
		cancel(nil)
		_ = monitor.Close()
		_ = t.close()
		browser.Close()
		workers.Wait()
	}()
	send := func(event observationEvent) bool {
		select {
		case <-stop.Done():
			return false
		case events <- event:
			return true
		default:
			cancel(errors.New("collector observation queue exhausted"))
			return false
		}
	}
	workers.Go(func() {
		_ = monitor.Wait()
		_ = t.close() // Invalidate sockets before any reused link index can send.
		cancel(errors.New("collector link or address generation changed"))
	})
	workers.Go(func() {
		for {
			hint, err := browser.Next(stop)
			if err != nil {
				cancel(err)
				return
			}
			if !send(observationEvent{hint: hint}) {
				return
			}
		}
	})
	for _, receiver := range t.receivers {
		workers.Go(func() {
			rejected := make(map[string]bool)
			report := func(err error) {
				if reason := err.Error(); !rejected[reason] && len(rejected) < 16 {
					rejected[reason] = true
					send(observationEvent{rejected: reason})
				}
			}
			for {
				packet, err := receiver.Receive()
				if errors.Is(err, observation.ErrPacketRejected) {
					report(err)
					continue
				}
				if err != nil {
					cancel(err)
					return
				}
				observed := catalog.Now()
				records, err := observation.Parse(packet, t.links, t.scopes, t.addresses, func(name string) (bool, error) {
					return c.identities.Owns(stop, name)
				})
				if err != nil {
					report(err)
					continue
				}
				if len(records) == 0 {
					continue // Invalid network data cannot renew evidence.
				}
				if !send(observationEvent{wire: records, now: observed}) {
					return
				}
			}
		})
	}
	// Process hints while bootstrapping: a large cached enumeration must not fill
	// the event queue merely because the collector has not reached its first tick.
	seeded := make(chan error, 1)
	workers.Go(func() {
		err := browser.Seed(stop)
		for index, link := range t.links {
			for _, family := range link.Families {
				for _, question := range c.settings.Bootstrap {
					if err == nil {
						_, err = browser.Watch(stop, avahi.Query{Interface: index, Family: family, Name: question.Name, Type: dns.StringToType[question.Type]})
					}
				}
			}
		}
		seeded <- err
	})
	cache := observation.New()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastCounts [6]uint64
	ready := false
	for {
		select {
		case <-stop.Done():
			return context.Cause(stop)
		case err := <-seeded:
			if err != nil {
				return err
			}
			ready = true
			c.mu.Lock()
			if stop.Err() == nil {
				c.current = epoch
			}
			c.mu.Unlock()
		case request := <-epoch.requests:
			request.reply <- c.browseDemand(request.ctx, browser, t, request.question)
		case event := <-events:
			if event.rejected != "" {
				if err := log.Encode(map[string]string{"event": "packet_rejected", "reason": event.rejected}); err != nil {
					return err
				}
			} else if event.hint.Epoch != "" {
				if err := cache.Hint(event.hint.Epoch, event.hint.Record, event.hint.Added); err != nil {
					return err
				}
				if err := browser.Follow(stop, event.hint); err != nil {
					return err
				}
			} else if err := cache.IngestAt(event.wire, event.now.Mono, catalog.Now().Mono); err != nil {
				return err
			}
		case <-ticker.C:
			if !ready {
				continue
			}
			if err := browser.Err(); err != nil {
				return err
			}
			now := catalog.Now()
			records, err := cache.Records(now)
			if err != nil {
				return err
			}
			records, groups, err := c.views(stop, records, t.links, now)
			if err != nil {
				return err
			}
			if err := producer.Send(stop, groups); err != nil {
				var conflict *publication.Conflict
				if errors.As(err, &conflict) {
					bounded, cancel := context.WithTimeout(context.WithoutCancel(stop), 2*time.Second)
					resolveErr := c.identities.ResolveConflicts(bounded, conflict.Names)
					cancel()
					return errors.Join(err, resolveErr)
				}
				return err
			}
			c.mu.Lock()
			if c.current == epoch && stop.Err() == nil && c.feed != nil {
				err = c.feed.Publish(podView(records, now.Wall), now.Wall, catalog.Now())
			}
			c.mu.Unlock()
			if err != nil {
				return err
			}
			if err := browser.Retire(stop); err != nil {
				return err
			}
			if err := notify(stop); err != nil {
				return err
			}
			wire, hints := cache.Counts()
			watches, _, deferred := browser.Counts()
			published := 0
			for _, group := range groups {
				published += len(group.Records)
			}
			counts := [6]uint64{uint64(wire), uint64(hints), uint64(len(records)), uint64(published), uint64(watches), deferred}
			if counts != lastCounts {
				if err := log.Encode(map[string]any{"event": "catalog_counts", "wire": wire, "hints": hints, "correlated": len(records), "published": published, "browsers": watches, "deferred": deferred}); err != nil {
					return err
				}
				lastCounts = counts
			}
		}
	}
}

func listen(ctx context.Context, endpoint config.Endpoint) (net.Listener, error) {
	address, err := netip.ParseAddr(endpoint.Host)
	if err != nil {
		return nil, err
	}
	family := "tcp4"
	if address.Is6() {
		family = "tcp6"
	}
	return (&net.ListenConfig{}).Listen(ctx, family, net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)))
}

// RunCollector assembles wire evidence, scoped Avahi browsing and optional HTTP
// delivery in one process. Any failed epoch withdraws before a bounded retry.
func RunCollector(ctx context.Context, settings config.Router, output io.Writer) (err error) {
	if err := settings.Validate(); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	identities, err := state.Open(ctx, settings.State, settings.AliasPrefix)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, identities.Close()) }()
	c := &collector{identities: identities, settings: settings}
	c.translator, err = translation.New(settings.Translators, settings.Interfaces)
	if err != nil {
		return err
	}
	stop, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var servers sync.WaitGroup
	defer func() { cancel(nil); servers.Wait() }()
	if c.translator != nil {
		servers.Go(func() { c.translator.Run(stop) })
	}
	if settings.Publication != nil {
		scopes, err := settings.Policy()
		if err != nil {
			return err
		}
		c.services, err = services.NewReceiver(settings.Publication.Source, scopes)
		if err != nil {
			return err
		}
		listener, err := listen(stop, settings.Publication.Endpoint)
		if err != nil {
			return err
		}
		clients, err := settings.Publication.Prefixes()
		if err != nil {
			return errors.Join(err, listener.Close())
		}
		servers.Go(func() { cancel(gateway.Serve(stop, listener, clients, c.services.API())) })
	}
	if settings.Gateway != nil {
		scopes, err := settings.Policy()
		if err != nil {
			return err
		}
		c.feed, err = gateway.NewFeed(stop, scopes, settings.State+".feed")
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, c.feed.Close()) }()
		if c.translator != nil {
			c.feed.Render = c.translator.Render
		}
		lookups := gateway.NewLookups(c.demand)
		defer lookups.Close()
		listener, err := listen(stop, settings.Gateway.Endpoint)
		if err != nil {
			return err
		}
		clients, err := settings.Gateway.Prefixes()
		if err != nil {
			return errors.Join(err, listener.Close())
		}
		servers.Go(func() { cancel(gateway.Serve(stop, listener, clients, gateway.CatalogAPI(c.feed, lookups))) })
	}
	log := json.NewEncoder(output)
	delay := 500 * time.Millisecond
	for {
		began := time.Now()
		err := c.collect(stop, boot, log)
		if stop.Err() != nil {
			return context.Cause(stop)
		}
		if logErr := log.Encode(map[string]string{"event": "discovery_epoch_lost", "reason": err.Error()}); logErr != nil {
			return logErr
		}
		if time.Since(began) > 30*time.Second {
			delay = 500 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-stop.Done():
			timer.Stop()
			return context.Cause(stop)
		case <-timer.C:
		}
		delay = min(30*time.Second, 2*delay)
	}
}
