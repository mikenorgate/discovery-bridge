// Discovery Bridge supplies Linux mDNS discovery adapters and diagnostic tools.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/node"
	"github.com/mikenorgate/discovery-bridge/internal/registry"
	registrydata "github.com/mikenorgate/discovery-bridge/registry"
)

var version = "development"

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "broker" || args[0] == "worker") {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return runNode(ctx, args, stderr)
	}
	if len(args) == 1 && args[0] == "version" {
		if _, err := fmt.Fprintf(stdout, "discovery-bridge %s (%s)\n", version, runtime.Version()); err != nil {
			return 1
		}
		return 0
	}
	if len(args) < 2 || args[0] != "registry" || args[1] != "describe" {
		if _, err := fmt.Fprintln(stderr, "usage: discovery-bridge version | registry describe [--locale language] _service._tcp | broker --config path [--node name]"); err != nil {
			return 1
		}
		return 2
	}
	flags := flag.NewFlagSet("registry describe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	locale := flags.String("locale", "", "Avahi description language")
	if err := flags.Parse(args[2:]); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		return 2
	}
	r, err := registry.Load(registrydata.Files)
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	description, err := r.Describe(flags.Arg(0), *locale)
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(map[string]string{"type": flags.Arg(0), "description": description, "registry_digest": r.Digest()}); err != nil {
		return 1
	}
	return 0
}

func runNode(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var err error
	if args[0] == "broker" {
		path := flags.String("config", "", "absolute node configuration path")
		name := flags.String("node", "", "downward API node name")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" {
			return 2
		}
		var settings config.Node
		settings, err = config.LoadNode(*path, *name)
		if err == nil {
			err = node.RunBroker(ctx, settings, stderr)
		}
	} else {
		fd := flags.Int("control-fd", -1, "inherited broker descriptor")
		parent := flags.Int("parent", -1, "broker parent PID")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		err = node.RunWorker(ctx, *fd, *parent)
	}
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	if _, writeErr := fmt.Fprintln(stderr, "discovery stopped:", err); writeErr != nil {
		return 1
	}
	return 1
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
