// Package router assembles scoped collector and independent publisher processes.
package router

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

type socketKey struct{ index, family int }

// topology belongs to one captured link epoch and owns all its raw sockets.
type topology struct {
	links     map[int]observation.Link
	addresses map[int][]netip.Addr
	receivers []*observation.Receiver
	senders   map[socketKey]*observation.Sender
	scopes    *policy.SourcePolicy
	once      sync.Once
	closeErr  error
}

func capture(settings config.Router, receive bool) (_ *topology, err error) {
	scopes, err := settings.Policy()
	if err != nil {
		return nil, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	generation := hex.EncodeToString(token[:])
	t := &topology{links: make(map[int]observation.Link), addresses: make(map[int][]netip.Addr), senders: make(map[socketKey]*observation.Sender), scopes: scopes}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.close())
		}
	}()
	for _, lan := range settings.Interfaces {
		iface, err := linuxnet.CurrentInterface(lan.Interface)
		if err != nil {
			return nil, err
		}
		if _, duplicate := t.links[iface.Index]; duplicate {
			return nil, errors.New("LAN interfaces resolved to a duplicate index")
		}
		families := slices.Clone(lan.Families)
		slices.Sort(families)
		for _, address := range iface.Addresses {
			if !address.Is6() || !address.IsLinkLocalUnicast() {
				if err := scopes.CheckAddress(lan.Source, address); err != nil {
					return nil, err
				}
			}
		}
		t.links[iface.Index] = observation.Link{Source: lan.Source, Generation: generation, Families: families}
		t.addresses[iface.Index] = iface.Addresses
		for _, family := range families {
			if receive {
				r, err := observation.OpenReceiver(lan.Interface, iface.Index, generation, family, iface.Addresses)
				if err != nil {
					return nil, err
				}
				t.receivers = append(t.receivers, r)
			}
			sender, err := observation.OpenSender(lan.Interface, iface.Index, family, iface.Addresses)
			if err != nil {
				return nil, err
			}
			t.senders[socketKey{iface.Index, family}] = sender
		}
	}
	return t, nil
}

func (t *topology) close() error {
	t.once.Do(func() {
		var errs []error
		for _, receiver := range t.receivers {
			errs = append(errs, receiver.Close())
		}
		for _, sender := range t.senders {
			errs = append(errs, sender.Close())
		}
		t.closeErr = errors.Join(errs...)
	})
	return t.closeErr
}
