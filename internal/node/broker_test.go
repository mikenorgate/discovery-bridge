package node

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

func TestConcurrentBrokerExpirySamplesClockInOrder(t *testing.T) {
	b := &Broker{leases: make(map[string]*lease)}
	start := make(chan struct{})
	errors := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			for range 1000 {
				if err := b.Expire(); err != nil {
					errors <- err
					return
				}
			}
		})
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error("concurrent expiry mistook reordered samples for clock regression", err)
	}
}

func TestBrokerExpiryRejectsActualClockRegression(t *testing.T) {
	b := &Broker{leases: map[string]*lease{"pod": {}}, lastTick: catalog.Now().Mono + time.Hour}
	if err := b.Expire(); err == nil || !strings.Contains(err.Error(), "clock moved backwards") || len(b.leases) != 0 {
		t.Fatal("clock regression was accepted", err)
	}
}
