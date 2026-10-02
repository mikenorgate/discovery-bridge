// Discovery Bridge supplies Linux mDNS discovery adapters and diagnostic tools.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/mikenorgate/discovery-bridge/internal/registry"
	registrydata "github.com/mikenorgate/discovery-bridge/registry"
)

var version = "development"

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		if _, err := fmt.Fprintf(stdout, "discovery-bridge %s (%s)\n", version, runtime.Version()); err != nil {
			return 1
		}
		return 0
	}
	if len(args) < 2 || args[0] != "registry" || args[1] != "describe" {
		if _, err := fmt.Fprintln(stderr, "usage: discovery-bridge version | registry describe [--locale language] _service._tcp"); err != nil {
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

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
