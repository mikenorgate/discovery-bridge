package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
)

// RunPublisher sends full leased replacements every five seconds. API failure
// sends an empty replacement; gateway failure leaves the old absolute lease.
func RunPublisher(ctx context.Context, settings config.ServicePublisher, output io.Writer) error {
	p, err := NewProducer(settings, nil)
	if err != nil {
		return err
	}
	client, err := gateway.NewClient(settings.Gateway)
	if err != nil {
		return err
	}
	log := json.NewEncoder(output)
	for ctx.Err() == nil {
		value, err := p.Snapshot(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			now := catalog.Now().Wall
			value = Snapshot{Schema: 1, Issued: now, Until: now.Add(Lease), Services: []Intent{}}
			if err := log.Encode(map[string]string{"event": "publication_source_unavailable"}); err != nil {
				return err
			}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := client.Post(ctx, "/v1/publications", data, http.StatusOK); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := log.Encode(map[string]string{"event": "publication_gateway_unavailable"}); err != nil {
				return err
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}
