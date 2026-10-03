package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serviceFixture() Service {
	return Service{Namespace: "services", Name: "example", Port: "http", Type: "_http._tcp", Instance: "Example web", TXT: map[string]string{"path": "/"}, Subtypes: []string{"test"}}
}

func servicePublisherFixture() ServicePublisher {
	return ServicePublisher{Enabled: true, Kubectl: []string{"/usr/bin/kubectl"}, Kubeconfig: "/etc/kubeconfig", Gateway: Endpoint{Host: "2001:db8:1::1", Port: 9444}, VIPNetworks: []string{"2001:db8:ff00::/60"}, Services: []Service{serviceFixture()}}
}

func TestServicePublicationRequiresExplicitMetadataAndVIPAuthority(t *testing.T) {
	for _, change := range []func(*ServicePublisher){
		func(s *ServicePublisher) { s.Enabled = false }, func(s *ServicePublisher) { s.VIPNetworks = nil },
		func(s *ServicePublisher) { s.Kubeconfig = "relative" }, func(s *ServicePublisher) { s.Kubectl = []string{"kubectl"} },
		func(s *ServicePublisher) { s.Gateway.Host = "gateway.local" }, func(s *ServicePublisher) { s.Services = nil },
		func(s *ServicePublisher) { s.Services = append(s.Services, s.Services[0]) },
		func(s *ServicePublisher) { s.Services[0].TXT = nil }, func(s *ServicePublisher) { s.Services[0].Subtypes = nil },
		func(s *ServicePublisher) { s.Services[0].Type = "_123._tcp" }, func(s *ServicePublisher) { s.Services[0].Type = "_http._sctp" },
		func(s *ServicePublisher) { s.Services[0].Instance = strings.Repeat("é", 17) },
		func(s *ServicePublisher) { s.Services[0].Namespace = "../../other" },
		func(s *ServicePublisher) { s.Services[0].Port = "other?query=1" },
		func(s *ServicePublisher) { s.Services[0].TXT = map[string]string{"bad=key": "x"} },
		func(s *ServicePublisher) { s.Services[0].TXT["key"] = strings.Repeat("x", 256) },
		func(s *ServicePublisher) { s.Services[0].Subtypes = []string{"test", "TEST"} },
	} {
		s := servicePublisherFixture()
		change(&s)
		if err := s.Validate(); err == nil {
			t.Fatal("unsafe Service configuration accepted", s)
		}
	}
	s := servicePublisherFixture()
	s.Services[0].Type = "_unregistered._udp"
	if err := s.Validate(); err != nil {
		t.Fatal("registry became a publication allowlist", err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServicePublisher(path); err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"services":[]}`)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServicePublisher(path); err == nil {
		t.Fatal("duplicate selection authority accepted")
	}
}

func TestPublicationListenerHasSeparateSourceAndClientAdmission(t *testing.T) {
	fixture := func() Router {
		r := routerFixture()
		r.Sources["kubernetes"] = []string{"2001:db8:ff00::/60"}
		r.Publication = &PublicationListener{Listener: Listener{Endpoint: Endpoint{Host: "2001:db8:2::1", Port: 9444}, Clients: []string{"2001:db8:3::/64"}}, Source: "kubernetes"}
		return r
	}
	for _, change := range []func(*Router){
		func(r *Router) { r.Publication.Source = "lan-a" }, func(r *Router) { r.Publication.Source = "missing" },
		func(r *Router) { r.Publication.Endpoint = r.Gateway.Endpoint }, func(r *Router) { r.Publication.Clients = nil },
		func(r *Router) { r.Publication.Clients = []string{"::/0"} }, func(r *Router) { r.Sources["kubernetes"] = []string{"2001:db8:1::/64"} },
	} {
		r := fixture()
		change(&r)
		if err := r.Validate(); err == nil {
			t.Fatal("ambiguous publication boundary accepted")
		}
	}
	if err := fixture().Validate(); err != nil {
		t.Fatal(err)
	}
}
