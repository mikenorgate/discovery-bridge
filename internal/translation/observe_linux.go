package translation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/command"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/jsonwire"
)

// Only the kernel fields needed for readiness are interpreted. ip may add
// unrelated fields; jsonwire still rejects duplicate keys throughout the input.
type link struct {
	Name  string   `json:"ifname"`
	Flags []string `json:"flags"`
	Info  struct {
		Kind string `json:"info_kind"`
		Data struct {
			Type string `json:"type"`
		} `json:"info_data"`
	} `json:"linkinfo"`
	Addresses []struct {
		Local      string          `json:"local"`
		Tentative  bool            `json:"tentative"`
		Deprecated bool            `json:"deprecated"`
		Valid      json.RawMessage `json:"valid_life_time"`
		Preferred  json.RawMessage `json:"preferred_life_time"`
	} `json:"addr_info"`
}

type route struct {
	Destination string          `json:"dst"`
	Device      string          `json:"dev"`
	Type        string          `json:"type"`
	Gateway     string          `json:"gateway"`
	Multipath   json.RawMessage `json:"multipath,omitempty"`
	Nexthops    json.RawMessage `json:"nexthops,omitempty"`
	Flags       []string        `json:"flags"`
}

func decodeList[T any](data []byte, maximum int) ([]T, error) {
	var raw []map[string]json.RawMessage
	if err := jsonwire.Decode(data, 1_048_576, &raw); err != nil {
		return nil, err
	}
	if raw == nil || len(raw) > maximum {
		return nil, errors.New("bounded kernel observation required")
	}
	var result []T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (r route) usable() bool {
	return (r.Type == "" || r.Type == "unicast") && len(r.Multipath) == 0 && len(r.Nexthops) == 0 && !slices.Contains(r.Flags, "linkdown") && !slices.Contains(r.Flags, "dead")
}

func installed(profile config.Translator, spaces catalog.Translation, nat46 bool, links []link, routes []route) bool {
	count := 0
	for _, l := range links {
		if l.Name != profile.Interface {
			continue
		}
		count++
		if !slices.Contains(l.Flags, "UP") || l.Info.Kind != "tun" || l.Info.Data.Type != "tun" {
			return false
		}
		addresses := make(map[string]bool)
		for _, a := range l.Addresses {
			if !a.Tentative && !a.Deprecated && string(a.Valid) != "0" && string(a.Preferred) != "0" {
				addresses[a.Local] = true
			}
		}
		if !addresses[profile.IPv4] || !addresses[profile.IPv6] {
			return false
		}
	}
	if count != 1 {
		return false
	}
	pool := profile.DynamicPool
	if nat46 {
		pool = spaces.Pool.String()
	}
	found := make(map[string]bool)
	for _, r := range routes {
		if r.Device == profile.Interface && r.usable() && r.Gateway == "" {
			found[r.Destination] = true
		}
	}
	return found[profile.Prefix] && found[pool]
}

func targetRouted(target netip.Addr, routes []route, lans map[string]bool) bool {
	longest, allowed := -1, false
	for _, r := range routes {
		destination := r.Destination
		if destination == "default" || destination == "" {
			destination = "::/0"
		}
		prefix, err := netip.ParsePrefix(destination)
		if err != nil {
			if address, parseErr := netip.ParseAddr(destination); parseErr == nil {
				prefix, err = netip.PrefixFrom(address, address.BitLen()), nil
			}
		}
		if err != nil || !prefix.Addr().Is6() || !prefix.Contains(target) {
			continue
		}
		if prefix.Bits() < longest {
			continue
		}
		valid := prefix.Bits() > 0 && lans[r.Device] && r.usable()
		if prefix.Bits() > longest {
			longest, allowed = prefix.Bits(), valid
		} else {
			allowed = allowed && valid
		}
	}
	return allowed
}

type service struct {
	PID        int
	Invocation string
}

type observer struct {
	run  func(context.Context, []string, time.Duration, int) ([]byte, error)
	read func(string) ([]byte, error)
	args func(int) ([]byte, error)
}

func (o observer) service(ctx context.Context, settings config.Translators, profile config.Translator) (service, error) {
	argv := append(slices.Clone(settings.Systemctl), "show", profile.Unit, "--property=ActiveState,SubState,MainPID,InvocationID")
	data, err := o.run(ctx, argv, time.Second, 65536)
	if err != nil {
		return service{}, err
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		_, duplicate := fields[key]
		if !ok || duplicate || key != "ActiveState" && key != "SubState" && key != "MainPID" && key != "InvocationID" {
			return service{}, errors.New("invalid service identity")
		}
		fields[key] = value
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	id, decodeErr := hex.DecodeString(fields["InvocationID"])
	if len(fields) != 4 || fields["ActiveState"] != "active" || fields["SubState"] != "running" || err != nil || pid <= 1 || decodeErr != nil || len(id) != 16 {
		return service{}, errors.New("translator service is not running")
	}
	return service{pid, fields["InvocationID"]}, nil
}

func matchingArgs(data []byte, profile config.Translator) bool {
	// Permit the supported service's identity/pidfile options, but no alternate
	// config or reload/startup flags that could change the attested profile.
	args := strings.Split(string(data), "\x00")
	if len(args) < 5 || args[len(args)-1] != "" || args[0] != profile.Binary {
		return false
	}
	seen := make(map[string]bool)
	for i := 1; i < len(args)-1; i++ {
		option := args[i]
		if seen[option] {
			return false
		}
		seen[option] = true
		if option == "--nodetach" {
			continue
		}
		if i+1 >= len(args)-1 {
			return false
		}
		i++
		value := args[i]
		switch option {
		case "--config":
			if value != profile.Config {
				return false
			}
		case "--pidfile":
			if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\n") {
				return false
			}
		case "--user", "--group":
			if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\n \t") {
				return false
			}
		default:
			return false
		}
	}
	return seen["--nodetach"] && seen["--config"]
}

func (o observer) profile(ctx context.Context, settings config.Translators, profile config.Translator, spaces catalog.Translation, nat46 bool, links []link, routes []route) (map[netip.Addr]netip.Addr, uint64, error) {
	before, err := o.service(ctx, settings, profile)
	if err != nil {
		return nil, 0, err
	}
	data, err := o.read(profile.Config)
	if err != nil {
		return nil, 0, err
	}
	maps, err := parseConfig(data, profile, spaces, nat46)
	if err != nil {
		return nil, 0, err
	}
	args, err := o.args(before.PID)
	if err != nil || !matchingArgs(args, profile) || !installed(profile, spaces, nat46, links, routes) {
		return nil, 0, errors.New("translator config, process or kernel state mismatch")
	}
	after, err := o.service(ctx, settings, profile)
	if err != nil || before != after {
		return nil, 0, errors.New("translator service replaced during observation")
	}
	current, err := o.read(profile.Config)
	if err != nil || !bytes.Equal(current, data) {
		return nil, 0, errors.New("translator configuration changed during observation")
	}
	hash := sha256.Sum256(append(data, []byte(before.Invocation)...))
	var generation uint64
	for _, b := range hash[:7] {
		generation = generation<<8 | uint64(b)
	}
	return maps, generation + 1, nil
}

func (o observer) observe(ctx context.Context, settings config.Translators, spaces catalog.Translation, lans map[string]bool) readiness {
	result := readiness{observed: catalog.Now()}
	read := func(arguments ...string) ([]byte, error) {
		return o.run(ctx, append(slices.Clone(settings.IP), arguments...), time.Second, 1_048_576)
	}
	data, err := read("-j", "-d", "address", "show")
	if err != nil {
		return result
	}
	links, err := decodeList[link](data, 1024)
	if err != nil {
		return result
	}
	var routes []route
	for _, family := range []string{"-4", "-6"} {
		data, err := read("-j", family, "route", "show")
		if err != nil {
			return result
		}
		part, err := decodeList[route](data, 8192)
		if err != nil {
			return result
		}
		routes = append(routes, part...)
	}
	if settings.NAT46 != nil {
		maps, generation, err := o.profile(ctx, settings, *settings.NAT46, spaces, true, links, routes)
		if err == nil {
			result.maps, result.generation = make(map[netip.Addr]netip.Addr), generation
			for target, alias := range maps {
				if targetRouted(target, routes, lans) {
					result.maps[target] = alias
				}
			}
		}
	}
	if settings.NAT64 != nil {
		_, _, err := o.profile(ctx, settings, *settings.NAT64, spaces, false, links, routes)
		result.nat64 = err == nil
	}
	return result
}

func localObserver() observer {
	return observer{run: command.Run, read: immutableConfig, args: processArgs}
}
