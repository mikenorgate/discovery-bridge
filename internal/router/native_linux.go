package router

import (
	"context"
	"errors"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/avahi"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

// Query exposes only the active epoch's read-only native query interface.
func (c *collector) Query(ctx context.Context, question native.Question) (native.Result, error) {
	c.mu.Lock()
	epoch := c.current
	c.mu.Unlock()
	if epoch == nil || epoch.native == nil {
		return native.Result{}, native.ErrUnavailable
	}
	return epoch.native.Query(ctx, question)
}

func (c *collector) nativeInterest(ctx context.Context, browser *avahi.Browser, topology *topology, question native.Question) (func() error, error) {
	owned, err := c.identities.Owns(ctx, question.DNS.Name)
	if err != nil {
		return nil, err
	}
	if owned {
		return nil, errors.New("bridge publications cannot become native query targets")
	}
	cleanups := make([]func() error, 0, 2)
	cleanup := func() error {
		failures := make([]error, 0, len(cleanups))
		for _, release := range cleanups {
			failures = append(failures, release())
		}
		return errors.Join(failures...)
	}
	for index, link := range topology.links {
		if link.Source != question.Source {
			continue
		}
		for _, family := range link.Families {
			if question.DNS.Qtype != dns.TypeANY {
				release, err := browser.WatchNative(ctx, avahi.Query{
					Interface: index, Family: family, Name: question.DNS.Name, Type: question.DNS.Qtype,
				})
				if err != nil {
					return nil, errors.Join(err, cleanup())
				}
				cleanups = append(cleanups, release)
			}
			// Avahi's own cache is not renewable wire evidence. An initial empty
			// known-answer query obtains a fresh packet even when Avahi is cached.
			err := topology.senders[socketKey{index, family}].NativeQuestion(ctx, question.DNS, topology.scopes.Sources()[question.Source])
			if err != nil {
				return nil, errors.Join(err, cleanup())
			}
		}
		return cleanup, nil
	}
	return nil, native.ErrUnavailable
}
