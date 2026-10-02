package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
)

type datagram struct {
	endpoint *linuxnet.Endpoint
	wire     []byte
	peer     *net.UDPAddr
	err      error
}
type packetKey struct {
	family int
	peer   string
	digest [32]byte
}
type batchKey struct {
	family int
	peer   string
}
type queryBatch struct {
	query         responder.Query
	endpoint      *linuxnet.Endpoint
	peer          *net.UDPAddr
	due, expires  time.Duration
	size, packets int
	assembly      bool
}

// Session is a bounded answer-only loop for one independently leased namespace.
type Session struct {
	endpoints []*linuxnet.Endpoint
	feed      *catalog.NodeFeed
	client    *gateway.Client
	deadline  atomic.Int64
	cancel    context.CancelFunc
	done      chan struct{}
	once      sync.Once
}

func newSession(ctx context.Context, endpoints []*linuxnet.Endpoint, feed *catalog.NodeFeed, client *gateway.Client, deadline time.Duration) (*Session, error) {
	if len(endpoints) < 1 || len(endpoints) > 2 || deadline <= catalog.Now().Mono || deadline-catalog.Now().Mono > catalog.Lease {
		return nil, errors.New("fresh bounded pod lease required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s := &Session{endpoints: endpoints, feed: feed, client: client, cancel: cancel, done: make(chan struct{})}
	s.deadline.Store(int64(deadline))
	go s.run(runCtx)
	return s, nil
}

// Renew accepts only a broker-issued absolute monotonic eligibility deadline.
func (s *Session) Renew(deadline time.Duration) error {
	now := catalog.Now().Mono
	if deadline <= now || deadline-now > catalog.Lease {
		return errors.New("invalid eligibility renewal")
	}
	select {
	case <-s.done:
		return errors.New("closed pod session")
	default:
	}
	s.deadline.Store(int64(deadline))
	return nil
}

// Close cancels the loop and releases only its worker-owned sockets.
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		for _, endpoint := range s.endpoints {
			_ = endpoint.Close()
		}
	})
}

func (s *Session) run(ctx context.Context) {
	events := make(chan datagram, 32)
	var readers, requests sync.WaitGroup
	defer func() { s.Close(); readers.Wait(); requests.Wait(); close(s.done) }()
	for _, endpoint := range s.endpoints {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				wire, peer, err := endpoint.Receive()
				if errors.Is(err, linuxnet.ErrDatagramRejected) {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				select {
				case <-ctx.Done():
					return
				case events <- datagram{endpoint, wire, peer, err}:
				}
				if err != nil {
					return
				}
			}
		}()
	}
	response := responder.New()
	ingress, egress := gateway.NewBucket(32, 64), gateway.NewBucket(10, 32)
	claims := make(map[string]time.Duration)
	loopback := make(map[packetKey]time.Duration)
	recent := make(map[packetKey]time.Duration)
	pending := make(map[batchKey]*queryBatch)
	ordinary := make(map[packetKey]*queryBatch)
	type lookup struct{ data []byte }
	lookups := make(chan lookup, 16)
	requests.Add(1)
	go func() {
		defer requests.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case value := <-lookups:
				requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, _ = s.client.Post(requestCtx, "/v1/lookup", value.data, 202)
				cancel()
			}
		}
	}()
	blocked := func(now time.Duration) map[string]bool {
		result := make(map[string]bool)
		for name, until := range claims {
			if now >= until {
				delete(claims, name)
			} else {
				result[name] = true
			}
		}
		return result
	}
	view := func(now catalog.Moment) []catalog.Answer {
		answers := s.feed.ViewBlocked(now, blocked(now.Mono))
		ttl := time.Duration(s.deadline.Load()) - now.Mono
		if ttl < time.Second {
			return nil
		}
		limit := uint32(min(ttl/time.Second, catalog.MaxTTL))
		for index := range answers {
			answers[index].RR = dns.Copy(answers[index].RR)
			answers[index].RR.Header().Ttl = min(answers[index].RR.Header().Ttl, limit)
		}
		return answers
	}
	send := func(endpoint *linuxnet.Endpoint, reply responder.Reply, peer *net.UDPAddr, now time.Duration) error {
		if !egress.Take(now, 1) {
			return nil
		}
		if err := endpoint.Send(reply.Wire, peer, !reply.Peer); err != nil {
			return err
		}
		response.NoteSent(reply, now)
		if !reply.Peer {
			loopback[packetKey{family: endpoint.Description.Family, digest: sha256.Sum256(reply.Wire)}] = now + 2*time.Second
		}
		return nil
	}
	answer := func(batch *queryBatch, now catalog.Moment) error {
		current := view(now)
		result, err := response.Build(batch.query, current, now.Mono, batch.peer.Port, batch.endpoint.Description.Family, 1232, false)
		if err != nil {
			return err
		}
		for _, reply := range result.Replies {
			if err := send(batch.endpoint, reply, batch.peer, catalog.Now().Mono); err != nil {
				return err
			}
		}
		withheld := blocked(now.Mono)
		var questions []responder.Question
		for _, q := range batch.query.Questions {
			if !withheld[catalog.NameKey(q.Name)] && (q.Type == dns.TypePTR || slices.Contains(result.Misses, q)) {
				if !slices.Contains(questions, q) {
					questions = append(questions, q)
				}
			}
		}
		for offset := 0; offset < len(questions); offset += 16 {
			q := responder.Query{Questions: questions[offset:min(offset+16, len(questions))]}
			value, err := q.Lookup()
			if err != nil {
				continue
			}
			data, err := jsonwire.Encode(value)
			if err != nil {
				continue
			}
			select {
			case lookups <- lookup{data}:
			default:
			}
		}
		return nil
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	nextWithdrawal := time.Duration(0)
	for {
		now := catalog.Now()
		if now.Mono >= time.Duration(s.deadline.Load()) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if event.err != nil {
				return
			}
			now = catalog.Now()
			key := packetKey{family: event.endpoint.Description.Family, peer: event.peer.String(), digest: sha256.Sum256(event.wire)}
			if loopback[packetKey{family: key.family, digest: key.digest}] > now.Mono {
				continue
			}
			if !ingress.Take(now.Mono, 1) {
				delete(pending, batchKey{key.family, key.peer})
				continue
			}
			if event.peer.Port == 5353 {
				consumed, err := observeClaims(event.wire, now.Mono, claims)
				if err != nil {
					if errors.Is(err, errClaimCapacity) {
						return
					}
					continue
				}
				if consumed {
					nextWithdrawal = 0
					continue
				}
			}
			q, err := responder.Parse(event.wire, true)
			if err != nil {
				continue
			}
			batchID := batchKey{key.family, key.peer}
			batch := pending[batchID]
			if q.Truncated || len(q.Questions) == 0 || (batch != nil && batch.assembly && slices.Equal(q.Questions, batch.query.Questions)) {
				if event.peer.Port != 5353 || (batch == nil && len(q.Questions) == 0) {
					continue
				}
				if batch == nil {
					if len(pending)+len(ordinary) >= 16 {
						continue
					}
					batch = &queryBatch{query: q, endpoint: event.endpoint, peer: event.peer, due: now.Mono + 400*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond))), expires: now.Mono + 2*time.Second, assembly: true}
					batch.query.Known = nil
					pending[batchID] = batch
				} else if !batch.assembly || (len(q.Questions) > 0 && (!slices.Equal(q.Questions, batch.query.Questions) || !slices.Equal(q.Unicast, batch.query.Unicast))) {
					delete(pending, batchID)
					continue
				}
				batch.size += len(event.wire)
				batch.packets++
				known := make(map[string]dns.RR)
				for _, rr := range append(slices.Clone(batch.query.Known), q.Known...) {
					key := (catalog.Answer{RR: rr}).Key()
					if previous, ok := known[key]; !ok || rr.Header().Ttl > previous.Header().Ttl {
						known[key] = rr
					}
				}
				if batch.size > 32768 || batch.packets > 16 || len(known) > 128 || now.Mono >= batch.expires {
					delete(pending, batchID)
					continue
				}
				batch.query.Known = nil
				for _, rr := range known {
					batch.query.Known = append(batch.query.Known, rr)
				}
				if q.Truncated {
					batch.due = now.Mono + 400*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond)))
				}
				continue
			}
			if len(pending)+len(ordinary) >= 16 || recent[key] > now.Mono {
				continue
			}
			recent[key] = now.Mono + time.Second
			for len(recent) > 128 {
				for key := range recent {
					delete(recent, key)
					break
				}
			}
			due := now.Mono
			if event.peer.Port == 5353 {
				due += 20*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond)))
			}
			ordinary[key] = &queryBatch{query: q, endpoint: event.endpoint, peer: event.peer, due: due, expires: now.Mono + 2*time.Second}
		case <-ticker.C:
			now = catalog.Now()
			for key, until := range loopback {
				if now.Mono >= until {
					delete(loopback, key)
				}
			}
			for key, until := range recent {
				if now.Mono >= until {
					delete(recent, key)
				}
			}
			for key, batch := range pending {
				if now.Mono >= batch.expires {
					delete(pending, key)
					continue
				}
				if now.Mono < batch.due {
					continue
				}
				delete(pending, key)
				batch.query.Truncated = false
				if err := answer(batch, now); err != nil {
					return
				}
			}
			for key, batch := range ordinary {
				if now.Mono >= batch.expires {
					delete(ordinary, key)
					continue
				}
				if now.Mono < batch.due {
					continue
				}
				delete(ordinary, key)
				if err := answer(batch, now); err != nil {
					return
				}
			}
			if now.Mono >= nextWithdrawal {
				current := view(now)
				for _, endpoint := range s.endpoints {
					replies, err := response.Withdrawals(current, endpoint.Description.Family)
					if err != nil {
						return
					}
					for _, reply := range replies {
						peer := &net.UDPAddr{Port: 5353}
						for _, address := range endpoint.Description.Addresses {
							if (endpoint.Description.Family == 4 && address.Is4()) || (endpoint.Description.Family == 6 && address.Is6()) {
								peer.IP = net.IP(address.AsSlice())
								break
							}
						}
						if err := send(endpoint, reply, peer, catalog.Now().Mono); err != nil {
							return
						}
					}
				}
				nextWithdrawal = now.Mono + time.Second
			}
		}
	}
}

var errClaimCapacity = errors.New("local claim capacity exceeded")

func observeClaims(wire []byte, now time.Duration, claims map[string]time.Duration) (bool, error) {
	if len(wire) < 12 {
		return false, errors.New("invalid local claim packet")
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	response := flags&0x8000 != 0
	if !response && binary.BigEndian.Uint16(wire[8:10]) == 0 {
		return false, nil
	}
	if flags&0x780f != 0 {
		return false, errors.New("invalid local claim header")
	}
	message, err := responder.Message(wire)
	if err != nil {
		return false, err
	}
	for name, until := range claims {
		if now >= until {
			delete(claims, name)
		}
	}
	values := message.Ns
	if response {
		values = append(slices.Clone(message.Answer), message.Extra...)
	}
	for _, rr := range values {
		h := rr.Header()
		if h.Class&0x7fff != 1 || h.Ttl == 0 || !catalog.LocalName(h.Name) {
			continue
		}
		switch h.Rrtype {
		case dns.TypeA, dns.TypeAAAA, dns.TypeSRV, dns.TypeTXT:
		default:
			continue
		}
		name := catalog.NameKey(h.Name)
		if claims[name] == 0 && len(claims) >= 256 {
			return true, errClaimCapacity
		}
		claims[name] = max(claims[name], now+time.Duration(h.Ttl)*time.Second)
	}
	return true, nil
}
