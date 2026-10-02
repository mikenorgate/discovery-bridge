package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"golang.org/x/sys/unix"
)

type controlMessage struct {
	data json.RawMessage
	fds  []int
	err  error
}
type workerSession struct {
	session *Session
	token   string
}

func secondsDeadline(value float64) (time.Duration, error) {
	now := catalog.Now().Mono.Seconds()
	if math.IsNaN(value) || math.IsInf(value, 0) || value <= now || value-now > 30 {
		return 0, errors.New("invalid absolute eligibility deadline")
	}
	return time.Duration(value * float64(time.Second)), nil
}

func applyControl(ctx context.Context, value controlMessage, sessions map[string]workerSession, feed *catalog.NodeFeed, client *gateway.Client) (_ bool, err error) {
	defer func() {
		for _, fd := range value.fds {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	var raw map[string]json.RawMessage
	if err := jsonwire.Decode(value.data, linuxnet.MaxMessage, &raw); err != nil {
		return false, err
	}
	var message struct {
		Op       string                 `json:"op"`
		UID      string                 `json:"uid"`
		Token    string                 `json:"token"`
		Deadline float64                `json:"deadline"`
		Sockets  []linuxnet.Description `json:"sockets"`
	}
	if err := jsonwire.Decode(value.data, linuxnet.MaxMessage, &message); err != nil {
		return false, err
	}
	if message.Op == "ping" && len(raw) == 1 && len(value.fds) == 0 {
		return true, nil
	}
	fields := map[string]bool{"op": true, "uid": true, "token": true}
	if message.Op == "open" || message.Op == "renew" {
		fields["deadline"] = true
	}
	if message.Op == "open" {
		fields["sockets"] = true
	}
	if message.Op != "open" && message.Op != "renew" && message.Op != "remove" {
		return false, errors.New("unknown broker operation")
	}
	if len(fields) != len(raw) {
		return false, errors.New("invalid broker operation fields")
	}
	for key := range raw {
		if !fields[key] {
			return false, errors.New("unexpected broker operation field")
		}
	}
	if message.UID == "" || len(message.UID) > 128 || len(message.Token) != 32 {
		return false, errors.New("invalid broker identity")
	}
	if _, err := hex.DecodeString(message.Token); err != nil {
		return false, errors.New("invalid broker token")
	}
	if message.Op != "open" && len(value.fds) > 0 {
		return false, errors.New("unexpected socket descriptors")
	}
	if message.Op == "open" {
		if _, exists := sessions[message.UID]; exists || len(sessions) >= 256 || len(value.fds) < 1 || len(value.fds) > 2 || len(message.Sockets) != len(value.fds) {
			return false, errors.New("invalid socket handoff capacity or identity")
		}
		deadline, err := secondsDeadline(message.Deadline)
		if err != nil {
			return false, err
		}
		var endpoints []*linuxnet.Endpoint
		defer func() {
			if err != nil {
				for _, endpoint := range endpoints {
					err = errors.Join(err, endpoint.Close())
				}
			}
		}()
		families := make(map[int]bool)
		for _, description := range message.Sockets {
			fd := value.fds[0]
			value.fds = value.fds[1:]
			endpoint, err := linuxnet.Adopt(os.NewFile(uintptr(fd), "broker pod socket"), description)
			if err != nil {
				return false, err
			}
			endpoints = append(endpoints, endpoint)
			if families[description.Family] {
				return false, errors.New("duplicate socket family")
			}
			families[description.Family] = true
		}
		session, err := newSession(ctx, endpoints, feed, client, deadline)
		if err != nil {
			return false, err
		}
		sessions[message.UID] = workerSession{session: session, token: message.Token}
		return false, nil
	}
	current, exists := sessions[message.UID]
	if !exists || current.token != message.Token {
		return false, errors.New("stale broker operation")
	}
	if message.Op == "remove" {
		current.session.Close()
		<-current.session.done
		delete(sessions, message.UID)
		return false, nil
	}
	deadline, err := secondsDeadline(message.Deadline)
	if err != nil {
		return false, err
	}
	return false, current.session.Renew(deadline)
}

// RunWorker consumes only broker configuration and pushed sockets/leases.
func RunWorker(ctx context.Context, fd, parent int) (err error) {
	if fd < 3 {
		return errors.New("private inherited control descriptor required")
	}
	if err := linuxnet.CheckWorkerConfinement(parent); err != nil {
		return err
	}
	channel := os.NewFile(uintptr(fd), "worker control")
	defer func() { _ = unix.Shutdown(fd, unix.SHUT_RDWR); err = errors.Join(err, channel.Close()) }()
	data, descriptors, err := linuxnet.Receive(fd)
	if err != nil {
		return err
	}
	if len(descriptors) > 0 {
		for _, descriptor := range descriptors {
			_ = unix.Close(descriptor)
		}
		return errors.New("configuration cannot carry sockets")
	}
	var settings config.Worker
	if err := jsonwire.Decode(data, linuxnet.MaxMessage, &settings); err != nil {
		return err
	}
	p, translated, err := settings.Policy()
	if err != nil {
		return err
	}
	feed := catalog.NewNodeFeed(p, translated)
	client, err := gateway.NewClient(settings.Gateway)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var refreshDone = make(chan struct{})
	go func() {
		defer close(refreshDone)
		for {
			_, _ = client.Refresh(runCtx, feed)
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	defer func() { cancel(); <-refreshDone }()
	sessions := make(map[string]workerSession)
	defer func() {
		for _, current := range sessions {
			current.session.Close()
		}
		for _, current := range sessions {
			<-current.session.done
		}
	}()
	control := make(chan controlMessage, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			data, fds, err := linuxnet.Receive(fd)
			value := controlMessage{data, fds, err}
			select {
			case control <- value:
			case <-runCtx.Done():
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		cancel()
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		<-readDone
		for {
			select {
			case value := <-control:
				for _, fd := range value.fds {
					_ = unix.Close(fd)
				}
			default:
				return
			}
		}
	}()
	lastPing := catalog.Now().Mono
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case value := <-control:
			if value.err != nil {
				return value.err
			}
			ping, err := applyControl(runCtx, value, sessions, feed, client)
			if err != nil {
				return err
			}
			if ping {
				lastPing = catalog.Now().Mono
			}
		case <-ticker.C:
			if catalog.Now().Mono-lastPing > 5*time.Second {
				return errors.New("broker heartbeat expired")
			}
		}
	}
}
