//go:build integration && linux

package services

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "fixture-kubectl" {
		if os.Args[len(os.Args)-1] == "--output=json" {
			_, _ = os.Stdout.WriteString(`{"clusters":[{"cluster":{"server":"https://api.example"}}]}`)
			os.Exit(0)
		}
		data, err := os.ReadFile(os.Getenv("DISCOVERY_BRIDGE_SERVICE_TEST_SOURCE"))
		if err != nil {
			panic(err)
		}
		var source map[string]json.RawMessage
		if err := json.Unmarshal(data, &source); err != nil {
			panic(err)
		}
		key := "service"
		if strings.Contains(os.Args[len(os.Args)-1], "endpointslices?") {
			key = "slices"
		}
		if _, err := os.Stdout.Write(source[key]); err != nil {
			panic(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestActualServicePublisherCLIPublishesAndWithdraws(t *testing.T) {
	binary := os.Getenv("DISCOVERY_BRIDGE_TEST_BINARY")
	if binary == "" {
		t.Skip("actual executable qualification uses DISCOVERY_BRIDGE_TEST_BINARY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	directory := t.TempDir()
	source := filepath.Join(directory, "api.json")
	writeSource := func(ready bool) {
		t.Helper()
		slice := sliceJSON
		if !ready {
			slice = strings.Replace(slice, `"ready":true`, `"ready":false`, 1)
		}
		data, err := json.Marshal(map[string]json.RawMessage{"service": []byte(serviceJSON), "slices": []byte(`{"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSliceList","items":[` + slice + `]}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source+".new", data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(source+".new", source); err != nil {
			t.Fatal(err)
		}
	}
	writeSource(true)
	r, err := NewReceiver("kubernetes", scope(t, "kubernetes"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiCtx, stopAPI := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() {
		finished <- gateway.Serve(apiCtx, listener, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, r.API())
	}()
	t.Cleanup(func() { stopAPI(); <-finished })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings := settings()
	settings.Kubectl = []string{self, "fixture-kubectl"}
	settings.Gateway = config.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "services.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "kubernetes-publisher", "--config", path)
	command.Env = append(os.Environ(), "GOMAXPROCS=2", "DISCOVERY_BRIDGE_SERVICE_TEST_SOURCE="+source)
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	wait := func(count int, timeout time.Duration) {
		t.Helper()
		for deadline := time.Now().Add(timeout); len(r.Records(catalog.Now())) != count; {
			if time.Now().After(deadline) {
				t.Fatal("actual Service producer did not reach expected record count", count)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	wait(6, 4*time.Second)
	status, err := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			if fields[1] != strconv.Itoa(os.Geteuid()) {
				t.Fatal("Service producer changed UID", line)
			}
		case "CapEff:":
			if fields[1] != "0000000000000000" {
				t.Fatal("Service producer retained capabilities", line)
			}
		case "NoNewPrivs:":
			if fields[1] != "1" {
				t.Fatal("Service producer lost no-new-privileges", line)
			}
		case "Threads:":
			count, err := strconv.Atoi(fields[1])
			if err != nil || count > 32 {
				t.Fatal("Service producer exceeded task budget", line)
			}
		}
	}
	for _, record := range r.Records(catalog.Now()) {
		if strings.Contains(record.Data, "3000") || strings.Contains(record.Data, "2001:db8:e000::10") || strings.Contains(record.Data, "2001:db8:f004::123") {
			t.Fatal("actual Service producer published a backend", record)
		}
	}
	writeSource(false)
	wait(0, 7*time.Second)
	writeSource(true)
	wait(6, 7*time.Second)
	if err := command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	wait(0, 17*time.Second)
	if err := command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	wait(6, 7*time.Second)
}
