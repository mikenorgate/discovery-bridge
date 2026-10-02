package registry_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/mikenorgate/discovery-bridge/internal/registry"
	registrydata "github.com/mikenorgate/discovery-bridge/registry"
)

func TestServiceNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, value, want string
		valid             bool
	}{
		{"standard", "HTTP", "http", true}, {"hyphen", "device-api", "device-api", true},
		{"digits only", "123", "", false}, {"underscore", "device_api", "", false},
		{"leading hyphen", "-device", "", false}, {"repeated hyphen", "device--api", "", false},
		{"long", "abcdefghijklmnop", "", false}, {"non ASCII", "dévices", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := registry.Identifier(test.value)
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf("got %q, %v; want %q, valid=%v", got, err, test.want, test.valid)
			}
		})
	}
}

func TestUnknownObservedTypesRemainAvailable(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"_private_thing._udp", "_presence_olpc._tcp.local.", "_HTTP._TCP.LOCAL."} {
		if _, err := registry.ObservedType(value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.GeneratedType("private_thing", "udp"); err == nil {
		t.Fatal("generated underscore name accepted")
	}
	if _, err := registry.GeneratedType("http", "sctp"); err == nil {
		t.Fatal("generated DNS-SD SCTP accepted")
	}
}

func TestPinnedRegistryAndMetadata(t *testing.T) {
	t.Parallel()
	r, err := registry.Load(registrydata.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, kind, locale, want string }{
		{"German", "_http._tcp", "de", "Web-Angebot"},
		{"locale fallback", "_http._tcp", "de_DE", "Web-Angebot"},
		{"registered", "_presence_olpc._tcp", "", "OLPC Presence"},
		{"unknown", "_private_thing._udp", "", "_private_thing._udp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := r.Describe(test.kind, test.locale)
			if err != nil || got != test.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
	rows := r.Metadata("http", "tcp")
	found := false
	for _, row := range rows {
		if row["Port Number"] == "80" {
			found = true
		}
		row["Port Number"] = "changed"
	}
	if !found {
		t.Fatal("IANA HTTP metadata missing")
	}
	for _, row := range r.Metadata("http", "tcp") {
		if row["Port Number"] == "changed" {
			t.Fatal("metadata is mutable across callers")
		}
	}
	if len(r.Digest()) != 64 {
		t.Fatal("missing registry digest")
	}
}

func TestRegistryTamperingFails(t *testing.T) {
	t.Parallel()
	files := fstest.MapFS{}
	for _, name := range []string{"manifest.json", "service-types", "iana.csv", "COPYING.avahi"} {
		data, err := fs.ReadFile(registrydata.Files, name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = &fstest.MapFile{Data: data}
	}
	files["service-types"].Data = append(files["service-types"].Data, []byte("\nchanged\n")...)
	if _, err := registry.Load(files); err == nil {
		t.Fatal("tampered registry accepted")
	}
}
