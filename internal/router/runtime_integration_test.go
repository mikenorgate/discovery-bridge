//go:build integration && linux

package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
	"github.com/mikenorgate/discovery-bridge/internal/services"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// The compiled producer consumes CLI JSON exactly as on deployment. The fixture
// substitutes API data without a cluster or infrastructure credentials.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "kubectl" {
		for _, arg := range os.Args[2:] {
			if arg == "config" {
				_, _ = os.Stdout.WriteString(`{"clusters":[{"cluster":{"server":"https://fixture"}}]}`)
				os.Exit(0)
			}
		}
		data, err := os.ReadFile(os.Getenv("DISCOVERY_KUBERNETES_TEST_SOURCE"))
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

// Each role runs in a separate process under its own unprivileged UID. The
// enclosing lab has private mount and network namespaces, including /run.
func TestRouterRoleProcess(t *testing.T) {
	role := os.Getenv("DISCOVERY_BRIDGE_TEST_ROLE")
	if role == "" {
		return
	}
	unix.Umask(0007)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	if role == "kubernetes-publisher" {
		settings, err := config.LoadServicePublisher(os.Getenv("DISCOVERY_BRIDGE_TEST_CONFIG"))
		if err != nil {
			t.Fatal(err)
		}
		if err := services.RunPublisher(ctx, settings, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		return
	}
	settings, err := config.LoadRouter(os.Getenv("DISCOVERY_BRIDGE_TEST_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dbus.Connect("unix:path=" + settings.BusSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	for _, member := range []string{"SetHostName", "EntryGroupNew"} {
		if member == "EntryGroupNew" && role == "publisher" {
			continue
		}
		var args []any
		if member == "SetHostName" {
			args = []any{"forbidden"}
		}
		call := connection.Object("org.freedesktop.Avahi", "/").CallWithContext(ctx, "org.freedesktop.Avahi.Server."+member, 0, args...)
		var denied dbus.Error
		if !errors.As(call.Err, &denied) || denied.Name != "org.freedesktop.DBus.Error.AccessDenied" {
			t.Fatal("router account gained an unnecessary Avahi method", role, member, call.Err)
		}
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if role == "publisher" {
		err = RunPublisher(ctx, settings)
	} else {
		err = RunCollector(ctx, settings, os.Stdout)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type labProcess struct {
	command  *exec.Cmd
	finished chan struct{}
	err      error // Published by closing finished.
	log      string
}

func launch(t *testing.T, command *exec.Cmd, log string) *labProcess {
	t.Helper()
	file, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr = file, file
	if err := command.Start(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	p := &labProcess{command: command, finished: make(chan struct{}), log: log}
	go func() { p.err = command.Wait(); _ = file.Close(); close(p.finished) }()
	t.Cleanup(func() {
		if err := p.stop(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func (p *labProcess) stop() error {
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.finished:
	case <-time.After(3 * time.Second):
		if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case <-p.finished:
		case <-time.After(2 * time.Second):
			return errors.New("lab process did not exit after kill")
		}
	}
	return nil
}

func (p *labProcess) check(t *testing.T) {
	t.Helper()
	select {
	case <-p.finished:
		data, _ := os.ReadFile(p.log)
		t.Fatalf("lab process exited: %v\n%s", p.err, data)
	default:
	}
}

func TestRouterRuntimeWithRealAvahi(t *testing.T) {
	if os.Getenv("DISCOVERY_BRIDGE_TEST_LAB") == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", self, "-test.run=^TestRouterRuntimeWithRealAvahi$", "-test.timeout=75s", "-test.v")
		// All roles share this fixture's task budget. Match the two runtime
		// processors used under each deployed role's fractional CPU limit.
		command.Env = append(os.Environ(), "DISCOVERY_BRIDGE_TEST_LAB=1", "GOMAXPROCS=2")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated router lab: %v\n%s", err, output)
		}
		return
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=8m"); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "bridge-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chown(dir, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 105*time.Second)
	t.Cleanup(cancel)
	// A copy is needed because native go test build directories are root-only.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "role.test")
	input, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, input.Close(), output.Close()); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if data, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("lab interface setup: %v: %s", err, data)
		}
	}
	run("ip", "link", "set", "lo", "up")
	var peers []*linuxnet.Namespace
	var peerInterfaces []linuxnet.Interface
	for i := range 2 {
		child := launch(t, exec.CommandContext(ctx, "unshare", "--net", "sleep", "110"), filepath.Join(dir, "peer-"+strconv.Itoa(i)+".log"))
		var ns *linuxnet.Namespace
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			ns, err = linuxnet.Open("/proc", child.command.Process.Pid)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ns.Close() })
		lan, peer := "lan"+strconv.Itoa(i), "peer"+strconv.Itoa(i)
		run("ip", "link", "add", lan, "type", "veth", "peer", "name", peer)
		run("ip", "link", "set", peer, "netns", strconv.Itoa(child.command.Process.Pid))
		address4, address6 := "192.0.2.1/24", "2001:db8:1::1/64"
		peer4, peer6 := "192.0.2.42/24", "2001:db8:1::42/64"
		if i == 1 {
			address4, address6, peer4, peer6 = "198.51.100.1/24", "2001:db8:2::1/64", "198.51.100.42/24", "2001:db8:2::42/64"
		}
		run("ip", "address", "add", address4, "dev", lan)
		run("ip", "address", "add", address6, "dev", lan, "nodad")
		if i == 0 {
			// A secondary egress address shares the LAN interface but must not
			// become the source of discovery traffic or prevent startup.
			run("ip", "address", "add", "2001:db8::61/128", "dev", lan, "nodad")
		}
		run("ip", "link", "set", lan, "up")
		// Veth checksum offload leaves partial checksums in raw socket copies.
		// Emulate packets arriving from a NIC with completed wire checksums.
		run("ethtool", "--offload", lan, "tx", "off")
		peerRun := func(args ...string) {
			run(append([]string{"nsenter", "--target", strconv.Itoa(child.command.Process.Pid), "--net", "ip"}, args...)...)
		}
		peerRun("address", "add", peer4, "dev", peer)
		peerRun("address", "add", peer6, "dev", peer, "nodad")
		peerRun("link", "set", peer, "up")
		run("nsenter", "--target", strconv.Itoa(child.command.Process.Pid), "--net", "ethtool", "--offload", peer, "tx", "off")
		var iface linuxnet.Interface
		prefix4, err := netip.ParsePrefix(peer4)
		if err != nil {
			t.Fatal(err)
		}
		prefix6, err := netip.ParsePrefix(peer6)
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			iface, err = ns.Inspect(peer, []netip.Addr{prefix4.Addr(), prefix6.Addr()})
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		peers, peerInterfaces = append(peers, ns), append(peerInterfaces, iface)
	}
	bus := filepath.Join(dir, "bus")
	busConfig := filepath.Join(dir, "bus.conf")
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	policyPath := os.Getenv("DISCOVERY_BRIDGE_TEST_DBUS_POLICY")
	if policyPath == "" {
		policyPath = "../../packaging/dbus/org.discovery-bridge.conf"
	}
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Use existing test-image accounts; production sysusers create distinct IDs.
	policyData = []byte(strings.NewReplacer("discovery-bridge-collector", "nobody", "discovery-bridge-publisher", "daemon").Replace(string(policyData)))
	policyFile := filepath.Join(dir, "policy.conf")
	write(policyFile, policyData, 0644)
	write(busConfig, []byte(`<busconfig><type>system</type><listen>unix:path=`+bus+`</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy><include>`+policyFile+`</include></busconfig>`), 0644)
	busProcess := launch(t, exec.CommandContext(ctx, "dbus-daemon", "--nofork", "--nopidfile", "--config-file="+busConfig), filepath.Join(dir, "bus.log"))
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		busProcess.check(t)
		if _, err := os.Stat(bus); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	avahiConfig := filepath.Join(dir, "avahi.conf")
	write(avahiConfig, []byte("[server]\nhost-name=bridge-fixture\nuse-ipv4=yes\nuse-ipv6=yes\nallow-interfaces=lan0,lan1\nenable-dbus=yes\nratelimit-burst=10000\nentries-per-entry-group-max=4096\n[wide-area]\nenable-wide-area=no\n[publish]\npublish-addresses=no\npublish-hinfo=no\npublish-workstation=no\npublish-domain=no\n[reflector]\nenable-reflector=no\n"), 0644)
	avahiCommand := exec.CommandContext(ctx, "avahi-daemon", "--no-drop-root", "--no-chroot", "--no-rlimits", "--debug", "--file="+avahiConfig)
	avahiCommand.Env = append(os.Environ(), "DBUS_SYSTEM_BUS_ADDRESS=unix:path="+bus)
	avahiProcess := launch(t, avahiCommand, filepath.Join(dir, "avahi.log"))
	connection, err := dbus.Connect("unix:path=" + bus)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		avahiProcess.check(t)
		var state int32
		if err := connection.Object("org.freedesktop.Avahi", "/").CallWithContext(ctx, "org.freedesktop.Avahi.Server.GetState", 0).Store(&state); err == nil && state == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real Avahi did not reach running state")
		}
		time.Sleep(20 * time.Millisecond)
	}
	settings := config.Router{Enabled: true, Interfaces: []config.LAN{{Interface: "lan0", Source: "lan-a", Families: []int{4, 6}}, {Interface: "lan1", Source: "lan-b", Families: []int{4, 6}}}, Sources: map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}, "lan-b": {"198.51.100.0/24", "2001:db8:2::/64"}}, AliasPrefix: "bridge", BusSocket: bus, State: filepath.Join(dir, "identities.db"), PublisherSocket: filepath.Join(dir, "publisher.sock"), ProducerUser: "nobody", Gateway: &config.Listener{Endpoint: config.Endpoint{Host: "127.0.0.1", Port: 19443}, Clients: []string{"127.0.0.1/32"}}}
	settings.Forbidden = []string{"2001:db8::/64"}
	settings.Sources["kubernetes"] = []string{"2001:db8:ff00::/60"}
	settings.Publication = &config.PublicationListener{Listener: config.Listener{Endpoint: config.Endpoint{Host: "127.0.0.1", Port: 19444}, Clients: []string{"127.0.0.1/32"}}, Source: "kubernetes"}
	write(settings.State, nil, 0660)
	if err := os.Chmod(settings.State, 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(settings.State, 1, 65534); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "router.json")
	configData, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	write(configPath, configData, 0644)
	producerConfig := filepath.Join(dir, "services.json")
	producerSource := filepath.Join(dir, "api.json")
	selected := config.Service{Namespace: "services", Name: "example", Port: "http", Type: "_http._tcp", Instance: "Example web", TXT: map[string]string{"path": "/"}, Subtypes: []string{"test"}}
	producerSettings := config.ServicePublisher{Enabled: true, Kubectl: []string{binary, "kubectl"}, Kubeconfig: "/etc/fixture-kubeconfig", Gateway: settings.Publication.Endpoint, VIPNetworks: settings.Sources["kubernetes"], Services: []config.Service{selected}}
	data, err := json.Marshal(producerSettings)
	if err != nil {
		t.Fatal(err)
	}
	write(producerConfig, data, 0644)
	apiSource := func(ready bool) {
		t.Helper()
		service := json.RawMessage(`{"apiVersion":"v1","kind":"Service","metadata":{"namespace":"services","name":"example","uid":"service-uid","resourceVersion":"10"},"spec":{"type":"LoadBalancer","ports":[{"name":"http","protocol":"TCP","port":80,"targetPort":3000}],"clusterIP":"2001:db8:e000::10"},"status":{"loadBalancer":{"ingress":[{"ip":"2001:db8:ff00::22"}]}}}`)
		slices := json.RawMessage(`{"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSliceList","items":[{"metadata":{"namespace":"services","labels":{"kubernetes.io/service-name":"example"},"ownerReferences":[{"kind":"Service","uid":"service-uid","controller":true}]},"addressType":"IPv6","ports":[{"name":"http","protocol":"TCP","port":3000}],"endpoints":[{"addresses":["2001:db8:f004::123"],"conditions":{"ready":` + strconv.FormatBool(ready) + `}}]}]}`)
		data, err := json.Marshal(map[string]json.RawMessage{"service": service, "slices": slices})
		if err != nil {
			t.Fatal(err)
		}
		// Atomic replacement prevents the fixture from manufacturing partial API
		// responses while the compiled producer reads the file.
		write(producerSource+".new", data, 0644)
		if err := os.Rename(producerSource+".new", producerSource); err != nil {
			t.Fatal(err)
		}
	}
	apiSource(true)
	role := func(name string, uid uint32) *labProcess {
		path := configPath
		caps := []uintptr{unix.CAP_NET_RAW}
		if name == "kubernetes-publisher" {
			path, caps = producerConfig, nil
		}
		// Set this thread-local flag before exec so every Go runtime thread
		// inherits the boundary, including when testing the fixture executable.
		command := exec.CommandContext(ctx, "setpriv", "--no-new-privs", binary, "-test.run=^TestRouterRoleProcess$", "-test.v")
		if runtimeBinary := os.Getenv("DISCOVERY_BRIDGE_TEST_BINARY"); runtimeBinary != "" {
			// setpriv establishes the same no-new-privileges boundary that
			// systemd and the production container supply to the real binary.
			command = exec.CommandContext(ctx, "setpriv", "--no-new-privs", runtimeBinary, name, "--config", path)
		}
		command.Env = append(os.Environ(), "DISCOVERY_BRIDGE_TEST_ROLE="+name, "DISCOVERY_BRIDGE_TEST_CONFIG="+path, "DISCOVERY_KUBERNETES_TEST_SOURCE="+producerSource, "GORACE=atexit_sleep_ms=0")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 65534, Groups: []uint32{}}, AmbientCaps: caps}
		return launch(t, command, filepath.Join(dir, name+".log"))
	}
	for _, lan := range []string{"lan0", "lan1"} {
		for deadline := time.Now().Add(3 * time.Second); ; {
			if _, err := linuxnet.CurrentInterface(lan); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("router lab interface did not complete address readiness", lan)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	publisher := role("publisher", 1) // The fixture's daemon account exists in NSS.
	t.Cleanup(func() {
		if t.Failed() {
			for _, name := range []string{"bus.log", "avahi.log", "publisher.log", "collector.log", "kubernetes-publisher.log"} {
				if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
					t.Logf("%s:\n%s", name, data)
				}
			}
		}
	})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		publisher.check(t)
		if _, err := os.Stat(settings.PublisherSocket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	collector := role("collector", 65534)
	// Peer 0 supplies native responses; peer 1 observes cross-LAN publication.
	var producers []*net.UDPConn
	var receivers []*observation.Receiver
	for _, family := range []int{4, 6} {
		if err := peers[0].With(func() error {
			address, network := "192.0.2.42", "udp4"
			if family == 6 {
				address, network = "2001:db8:1::42", "udp6"
			}
			producer, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(address), Port: 5353})
			if err != nil {
				return err
			}
			producers = append(producers, producer)
			iface := peerInterfaces[0]
			if family == 4 {
				p := ipv4.NewPacketConn(producer)
				return errors.Join(p.SetMulticastInterface(&net.Interface{Index: iface.Index}), p.SetMulticastTTL(255))
			}
			p := ipv6.NewPacketConn(producer)
			return errors.Join(p.SetMulticastInterface(&net.Interface{Index: iface.Index}), p.SetMulticastHopLimit(255))
		}); err != nil {
			t.Fatal(err)
		}
		if err := peers[1].With(func() error {
			iface := peerInterfaces[1]
			r, err := observation.OpenReceiver("peer1", iface.Index, "test-peer", family, iface.Addresses)
			if err == nil {
				receivers = append(receivers, r)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, producer := range producers {
			_ = producer.Close()
		}
		for _, receiver := range receivers {
			_ = receiver.Close()
		}
	})
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}}
	for _, record := range deviceRecords(t, time.Now().UTC()) {
		rr, err := record.RR(12)
		if err != nil {
			t.Fatal(err)
		}
		if rr.Header().Rrtype != dns.TypePTR {
			rr.Header().Class |= 0x8000
		}
		message.Answer = append(message.Answer, rr)
	}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	send := func() {
		t.Helper()
		for i, producer := range producers {
			target := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
			if i == 1 {
				target.IP, target.Zone = net.ParseIP("ff02::fb"), strconv.Itoa(peerInterfaces[0].Index)
			}
			if _, err := producer.WriteToUDP(wire, target); err != nil {
				t.Fatal(err)
			}
		}
	}
	client, err := gateway.NewClient(settings.Gateway.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		t.Helper()
		data, err := client.Post(ctx, "/v1/catalog", []byte(`{"schema":1,"nonce":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}`), 200)
		if err != nil {
			return nil
		}
		return data
	}
	var payload struct {
		Snapshot catalog.Snapshot `json:"snapshot"`
	}
	for deadline := time.Now().Add(15 * time.Second); ; {
		collector.check(t)
		publisher.check(t)
		send()
		if err := json.Unmarshal(read(), &payload); err == nil && len(payload.Snapshot.Records) == 6 {
			break
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(collector.log)
			t.Fatalf("original DNS-SD graph absent from pod catalog: %+v\n%s", payload, data)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, record := range payload.Snapshot.Records {
		if record.Type == "SRV" && record.Data != "0 0 8080 sensor.local." {
			t.Fatal("application hostname renamed", record)
		}
	}
	serviceProducer := role("kubernetes-publisher", 65534)
	serviceCount := func() int {
		t.Helper()
		if err := json.Unmarshal(read(), &payload); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, record := range payload.Snapshot.Records {
			if record.Source != "kubernetes" {
				continue
			}
			count++
			if record.Data == "2001:db8:f004::123" || record.Data == "2001:db8:e000::10" {
				t.Fatal("backend appeared in pod discovery", record)
			}
			if record.Type == "SRV" && !strings.HasPrefix(record.Data, "0 0 80 kube-") {
				t.Fatal("Service target port or non-VIP target published", record)
			}
		}
		return count
	}
	waitServices := func(expected int, timeout time.Duration) {
		t.Helper()
		for deadline := time.Now().Add(timeout); ; {
			send()
			collector.check(t)
			publisher.check(t)
			// Shared enumeration RRsets carry the shortest member TTL. Allow
			// the next collector tick to restore the surviving native member.
			if serviceCount() == expected && (expected != 0 || len(payload.Snapshot.Records) == 6) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("Service discovery did not reach expected count", expected, payload)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitServices(6, 7*time.Second)
	for _, receiver := range receivers {
		if err := receiver.Socket.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		found := false
		for !found {
			packet, err := receiver.Receive()
			if err != nil {
				t.Fatal("Service LAN publication missing", err)
			}
			var response dns.Msg
			if err := response.Unpack(packet.Wire); err != nil {
				t.Fatal(err)
			}
			for _, rr := range response.Answer {
				if srv, ok := rr.(*dns.SRV); ok && srv.Port == 80 && srv.Hdr.Ttl == 1 && srv.Hdr.Class&0x8000 != 0 {
					found = true
				}
			}
		}
	}
	for _, process := range []*labProcess{publisher, collector, serviceProducer} {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(process.command.Process.Pid) + "/status")
		if err != nil {
			t.Fatal(err)
		}
		fields := make(map[string]string)
		for line := range strings.SplitSeq(string(data), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		caps := "0000000000002000"
		if process == serviceProducer {
			caps = "0000000000000000"
		}
		if fields["CapEff"] != caps || fields["CapPrm"] != caps || fields["NoNewPrivs"] != "1" || fields["Groups"] != "" {
			t.Fatal("router process gained unnecessary permissions", fields["CapEff"], fields["CapPrm"], fields["NoNewPrivs"], fields["Groups"])
		}
		threads, err := strconv.Atoi(fields["Threads"])
		if err != nil || threads > 32 {
			t.Fatal("router fixture exceeded its process thread budget", threads, err)
		}
		rssFields := strings.Fields(fields["VmRSS"])
		if len(rssFields) != 2 {
			t.Fatal("missing router resident memory sample")
		}
		rss, err := strconv.Atoi(rssFields[0])
		if err != nil || rss > 128*1024 {
			t.Fatal("router fixture exceeded its memory budget", rss, err)
		}
	}
	// Readiness loss becomes an empty full replacement and emits goodbyes without
	// withdrawing the continuously refreshed native device graph.
	apiSource(false)
	waitServices(0, 7*time.Second)
	for _, receiver := range receivers {
		if err := receiver.Socket.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		found := false
		for !found {
			packet, err := receiver.Receive()
			if err != nil {
				t.Fatal("Service goodbye missing", err)
			}
			var response dns.Msg
			if err := response.Unpack(packet.Wire); err != nil {
				t.Fatal(err)
			}
			for _, rr := range response.Answer {
				if srv, ok := rr.(*dns.SRV); ok && srv.Port == 80 && srv.Hdr.Ttl == 0 {
					found = true
				}
			}
		}
	}
	apiSource(true)
	waitServices(6, 7*time.Second)
	if err := serviceProducer.command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitServices(0, 17*time.Second)
	if len(payload.Snapshot.Records) != 6 {
		t.Fatal("expired Service intent disturbed native device discovery", payload.Snapshot.Records)
	}
	if err := serviceProducer.command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	waitServices(6, 7*time.Second)
	apiSource(false)
	waitServices(0, 7*time.Second)
	if err := serviceProducer.stop(); err != nil {
		t.Fatal(err)
	}
	if serviceProducer.err != nil {
		t.Fatal("Service producer did not stop cleanly", serviceProducer.err)
	}
	for i, receiver := range receivers {
		found := false
		if err := receiver.Socket.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for !found {
			packet, err := receiver.Receive()
			if err != nil {
				t.Fatal("cross-LAN publication missing", i, err)
			}
			if packet.HopLimit != 255 || packet.SourcePort != 5353 {
				t.Fatal("publication transport metadata", packet)
			}
			var answer dns.Msg
			if err := answer.Unpack(packet.Wire); err != nil {
				t.Fatal(err)
			}
			for _, rr := range answer.Answer {
				if rr.Header().Rrtype == dns.TypeSRV && rr.Header().Ttl == 1 && rr.Header().Class&0x8000 != 0 {
					found = true
				}
			}
		}
	}
	// A normal collector disconnect must clear both publication families while
	// leaving the independent publisher process healthy and able to accept again.
	if err := collector.stop(); err != nil {
		t.Fatal(err)
	}
	if collector.err != nil {
		data, _ := os.ReadFile(collector.log)
		t.Fatalf("collector did not stop cleanly: %v\n%s", collector.err, data)
	}
	for _, receiver := range receivers {
		if err := receiver.Socket.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for {
			packet, err := receiver.Receive()
			if err != nil {
				t.Fatal("publication goodbye missing", err)
			}
			var answer dns.Msg
			if err := answer.Unpack(packet.Wire); err != nil {
				t.Fatal(err)
			}
			goodbye := false
			for _, rr := range answer.Answer {
				goodbye = goodbye || rr.Header().Rrtype == dns.TypeSRV && rr.Header().Ttl == 0
			}
			if goodbye {
				break
			}
		}
	}
	publisher.check(t)
	// Reopening the collector cannot turn Avahi's cached hints into fresh wire
	// evidence. Fresh packets then restore the same permanent aliases.
	collector = role("collector", 65534)
	for deadline := time.Now().Add(4 * time.Second); ; {
		collector.check(t)
		if data := read(); len(data) > 0 {
			if err := json.Unmarshal(data, &payload); err != nil || len(payload.Snapshot.Records) != 0 {
				t.Fatal("cached hints repopulated a new collector epoch", string(data), err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted gateway unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for deadline := time.Now().Add(8 * time.Second); ; {
		send()
		collector.check(t)
		publisher.check(t)
		if err := json.Unmarshal(read(), &payload); err == nil && len(payload.Snapshot.Records) == 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh wire evidence did not restore discovery")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Even a stopped collector cannot hold publication past its last source
	// lease. The independent owner closes and a fresh owner can recover.
	if err := collector.command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-publisher.finished:
		if publisher.err == nil {
			t.Fatal("publisher hid producer lease expiry")
		}
	case <-time.After(14 * time.Second):
		t.Fatal("stopped collector retained LAN publication")
	}
	if err := collector.command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	publisher = role("publisher", 1)
	for deadline := time.Now().Add(8 * time.Second); ; {
		send()
		collector.check(t)
		publisher.check(t)
		if err := json.Unmarshal(read(), &payload); err == nil && len(payload.Snapshot.Records) == 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh publisher did not restore discovery")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// An approved link address change invalidates both independently captured
	// generations. The publisher exits so its systemd owner can reopen topology.
	run("ip", "address", "add", "198.51.100.2/24", "dev", "lan1")
	select {
	case <-publisher.finished:
		if publisher.err == nil {
			t.Fatal("publisher hid the topology failure")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("publisher retained an old link generation")
	}
}
