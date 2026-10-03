package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		args     []string
		code     int
		contains string
	}{
		{"version", []string{"version"}, 0, "go1.27.1"},
		{"localized registry", []string{"registry", "describe", "--locale", "de", "_http._tcp"}, 0, "Web-Angebot"},
		{"unknown observed type", []string{"registry", "describe", "_private_thing._udp"}, 0, "_private_thing._udp"},
		{"invalid type", []string{"registry", "describe", "_http._sctp"}, 2, ""},
		{"missing command", nil, 2, ""},
		{"publisher missing config", []string{"kubernetes-publisher"}, 2, ""},
		{"publisher extra argument", []string{"kubernetes-publisher", "--config", "/etc/fixture.json", "extra"}, 2, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(test.args, &stdout, &stderr)
			if code != test.code || !strings.Contains(stdout.String(), test.contains) {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
			}
		})
	}
}
