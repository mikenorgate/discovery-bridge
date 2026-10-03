package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func routerFixture() Router {
	return Router{Enabled: true, Interfaces: []LAN{{Interface: "lan0", Source: "lan-a", Families: []int{4, 6}}}, Sources: map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, AliasPrefix: "bridge", BusSocket: "/run/dbus/system_bus_socket", State: "/var/lib/discovery-bridge/identities.db", PublisherSocket: "/run/discovery-bridge/publisher.sock", ProducerUser: "discovery-collector", Gateway: &Listener{Endpoint: Endpoint{Host: "2001:db8:2::1", Port: 9443}, Clients: []string{"2001:db8:2::/64"}}}
}

func TestRouterRejectsImplicitTopologyAndPublicationAuthority(t *testing.T) {
	for _, change := range []func(*Router){
		func(r *Router) { r.Enabled = false },
		func(r *Router) { r.Interfaces[0].Families = nil },
		func(r *Router) { r.Interfaces[0].Families = []int{6, 6} },
		func(r *Router) { r.Interfaces = append(r.Interfaces, r.Interfaces[0]) },
		func(r *Router) { delete(r.Sources, "lan-a") },
		func(r *Router) { r.PublisherSocket = r.BusSocket },
		func(r *Router) { r.PublisherSocket = "relative.sock" },
		func(r *Router) { r.ProducerUser = "" },
		func(r *Router) { r.Gateway.Clients = []string{"::/0"} },
		func(r *Router) { r.Bootstrap = []Bootstrap{{Name: "sensor.example.", Type: "A"}} },
	} {
		r := routerFixture()
		change(&r)
		if err := r.Validate(); err == nil {
			t.Fatal("implicit or ambiguous router authority accepted", r)
		}
	}
	r := routerFixture()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "router.json")
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRouter(path); err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"enabled":true}`)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRouter(path); err == nil {
		t.Fatal("duplicate authority field accepted")
	}
}
