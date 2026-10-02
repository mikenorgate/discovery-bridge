package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
)

type lease struct {
	key, token   string
	namespace    *linuxnet.Namespace
	sockets      []*os.File
	descriptions []linuxnet.Description
	deadline     time.Duration
}

func (l *lease) close() error {
	var err error
	for _, file := range l.sockets {
		err = errors.Join(err, linuxnet.Revoke(file))
	}
	l.sockets = nil
	if l.namespace != nil {
		err = errors.Join(err, l.namespace.Close())
		l.namespace = nil
	}
	return err
}

type handed struct {
	token    string
	deadline time.Duration
}

// Broker retains independent socket ownership and eligibility deadlines.
type Broker struct {
	mu                           sync.Mutex
	settings                     config.Node
	runtime                      *Runtime
	leases                       map[string]*lease
	sent                         map[string]handed
	observed, lastPing, lastTick time.Duration
	closed                       bool
}

// NewBroker constructs a broker after configuration validation.
func NewBroker(settings config.Node, read ReadJSON) (*Broker, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &Broker{settings: settings, runtime: NewRuntime(settings, read), leases: make(map[string]*lease), sent: make(map[string]handed)}, nil
}

func (b *Broker) remove(uid string) error {
	l := b.leases[uid]
	if l == nil {
		return nil
	}
	delete(b.leases, uid)
	return l.close()
}

func (b *Broker) revokeAll() error {
	var err error
	for uid := range b.leases {
		err = errors.Join(err, b.remove(uid))
	}
	return err
}

// Expire runs independently of Kubernetes/runtime command progress.
func (b *Broker) Expire(now time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now < b.lastTick {
		return errors.Join(errors.New("broker clock moved backwards"), b.revokeAll())
	}
	b.lastTick = now
	var err error
	for uid, l := range b.leases {
		if now >= l.deadline {
			err = errors.Join(err, b.remove(uid))
		}
	}
	return err
}

// Reconcile admits only a fresh complete API list and verifies sandboxes twice.
func (b *Broker) Reconcile(ctx context.Context, items []json.RawMessage, observed time.Duration) error {
	selected := make(map[string]Pod)
	seen := make(map[string]bool)
	if items == nil || len(items) > 4096 {
		b.mu.Lock()
		defer b.mu.Unlock()
		return errors.Join(errors.New("bounded full pod list required"), b.revokeAll())
	}
	for _, raw := range items {
		var object podObject
		if err := json.Unmarshal(raw, &object); err != nil || object.Metadata.UID == "" || seen[object.Metadata.UID] {
			b.mu.Lock()
			defer b.mu.Unlock()
			return errors.Join(errors.New("malformed or duplicate pod identity"), b.revokeAll())
		}
		seen[object.Metadata.UID] = true
		if pod, ok := Select(raw, b.settings); ok {
			selected[pod.UID] = pod
		}
	}
	now := catalog.Now().Mono
	b.mu.Lock()
	if b.closed || observed < b.observed || now < observed || now-observed >= catalog.Lease {
		b.mu.Unlock()
		return errors.New("fresh monotonically ordered API observation required")
	}
	if len(selected) > 64 {
		err := b.revokeAll()
		b.mu.Unlock()
		return errors.Join(errors.New("eligible pod capacity exceeded"), err)
	}
	b.observed = observed
	for uid := range b.leases {
		if _, ok := selected[uid]; !ok {
			if err := b.remove(uid); err != nil {
				b.mu.Unlock()
				return err
			}
		}
	}
	b.mu.Unlock()
	keys := make([]string, 0, len(selected))
	for uid := range selected {
		keys = append(keys, uid)
	}
	slices.Sort(keys)
	for _, uid := range keys {
		remaining := observed + catalog.Lease - catalog.Now().Mono
		if remaining <= 0 || ctx.Err() != nil {
			break
		}
		verifyCtx, cancel := context.WithTimeout(ctx, remaining)
		err := b.admit(verifyCtx, selected[uid], observed+catalog.Lease)
		cancel()
		if err != nil {
			b.mu.Lock()
			closeErr := b.remove(uid)
			b.mu.Unlock()
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return b.Expire(catalog.Now().Mono)
}

func (b *Broker) admit(ctx context.Context, pod Pod, deadline time.Duration) (err error) {
	sandbox, err := b.runtime.Inspect(ctx, pod)
	if err != nil {
		return err
	}
	namespace, err := linuxnet.Open(b.settings.HostProc, sandbox.PID)
	if err != nil {
		return err
	}
	candidate := &lease{namespace: namespace, deadline: deadline}
	defer func() {
		if candidate != nil {
			err = errors.Join(err, candidate.close())
		}
	}()
	details, err := namespace.Inspect(b.settings.PodInterface, pod.Addresses)
	if err != nil {
		return err
	}
	key, err := namespace.Key()
	if err != nil {
		return err
	}
	candidate.key = fmt.Sprintf("%s:%s:%d:%v", sandbox.ID, key, details.Index, details.Addresses)
	b.mu.Lock()
	current := b.leases[pod.UID]
	if current != nil && current.key != candidate.key {
		err = b.remove(pod.UID)
		current = nil
	}
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if current == nil {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return err
		}
		candidate.token = hex.EncodeToString(token[:])
		for _, family := range []int{4, 6} {
			addresses := slices.Clone(details.Addresses)
			slices.SortStableFunc(addresses, func(a, b netip.Addr) int {
				af, bf := a.Is4(), b.Is4()
				if family == 6 {
					af, bf = a.Is6(), b.Is6()
				}
				if af && !bf {
					return -1
				}
				if bf && !af {
					return 1
				}
				return a.Compare(b)
			})
			if (family == 4 && !addresses[0].Is4()) || (family == 6 && !addresses[0].Is6()) {
				continue
			}
			file, err := namespace.Socket(b.settings.PodInterface, family)
			if err != nil {
				return err
			}
			candidate.sockets = append(candidate.sockets, file)
			candidate.descriptions = append(candidate.descriptions, linuxnet.Description{Index: details.Index, Family: family, Addresses: addresses})
		}
	}
	after, err := b.runtime.Inspect(ctx, pod)
	if err != nil || after.ID != sandbox.ID || after.PID != sandbox.PID {
		return errors.New("sandbox changed during admission")
	}
	verified, err := namespace.Inspect(b.settings.PodInterface, pod.Addresses)
	if err != nil || verified.Index != details.Index || !slices.Equal(verified.Addresses, details.Addresses) {
		return errors.New("interface changed during admission")
	}
	if err := namespace.Verify(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || catalog.Now().Mono >= deadline || ctx.Err() != nil {
		return errors.New("eligibility expired during admission")
	}
	if current != nil {
		if b.leases[pod.UID] != current {
			return errors.New("previous lease expired during admission")
		}
		current.deadline = deadline
	} else {
		b.leases[pod.UID] = candidate
		candidate = nil
	}
	return nil
}

// Sync pushes sockets and verified renewals; heartbeat alone cannot renew a pod.
func (b *Broker) Sync(channel int, now time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for uid, sent := range b.sent {
		current := b.leases[uid]
		if current == nil || current.token != sent.token {
			if err := linuxnet.Send(channel, map[string]any{"op": "remove", "uid": uid, "token": sent.token}, nil); err != nil {
				return err
			}
			delete(b.sent, uid)
		}
	}
	for uid, l := range b.leases {
		if now >= l.deadline {
			continue
		}
		sent := b.sent[uid]
		if sent.token != l.token {
			fds := make([]int, 0, len(l.sockets))
			for _, file := range l.sockets {
				fds = append(fds, int(file.Fd()))
			}
			if err := linuxnet.Send(channel, map[string]any{"op": "open", "uid": uid, "token": l.token, "deadline": l.deadline.Seconds(), "sockets": l.descriptions}, fds); err != nil {
				return err
			}
		} else if sent.deadline != l.deadline {
			if err := linuxnet.Send(channel, map[string]any{"op": "renew", "uid": uid, "token": l.token, "deadline": l.deadline.Seconds()}, nil); err != nil {
				return err
			}
		}
		b.sent[uid] = handed{l.token, l.deadline}
	}
	if now-b.lastPing >= 500*time.Millisecond {
		if err := linuxnet.Send(channel, map[string]string{"op": "ping"}, nil); err != nil {
			return err
		}
		b.lastPing = now
	}
	return nil
}

// Close independently revokes every retained socket and namespace descriptor.
func (b *Broker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return b.revokeAll()
}

// RunBroker starts one worker and services expiry while API/CRI reads proceed.
func RunBroker(ctx context.Context, settings config.Node, stderr io.Writer) (err error) {
	if err := settings.Validate(); err != nil {
		return err
	}
	broker, err := NewBroker(settings, CommandJSON)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, broker.Close()) }()
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	worker, err := linuxnet.StartWorker(runCtx, binary, nil, settings.WorkerUID, settings.WorkerGID, stderr)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, worker.Close()); <-worker.Done }()
	if err := linuxnet.Send(int(worker.Channel.Fd()), settings.Worker, nil); err != nil {
		return err
	}
	pods := NewPods(settings, CommandJSON)
	refreshed := make(chan error, 1)
	go func() {
		defer close(refreshed)
		for {
			items, observed, readErr := pods.Snapshot(runCtx)
			if readErr == nil {
				if err := broker.Reconcile(runCtx, items, observed); err != nil {
					refreshed <- err
					return
				}
			}
			timer := time.NewTimer(10 * time.Second)
			select {
			case <-runCtx.Done():
				timer.Stop()
				refreshed <- runCtx.Err()
				return
			case <-timer.C:
			}
		}
	}()
	defer func() { cancel(); <-refreshed }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-worker.Done:
			return errors.Join(errors.New("responder exited"), err)
		case err := <-refreshed:
			return err
		case <-ticker.C:
			now := catalog.Now().Mono
			if err := broker.Expire(now); err != nil {
				return err
			}
			if err := broker.Sync(int(worker.Channel.Fd()), now); err != nil {
				return err
			}
		}
	}
}
