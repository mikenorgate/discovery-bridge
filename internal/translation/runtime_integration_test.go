//go:build integration && linux

package translation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/config"
	"golang.org/x/sys/unix"
)

// The fixture holds a real TUN open and substitutes only systemctl's response.
// This qualifies read-only process/config/kernel readiness, not packet NAT.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--nodetach":
			fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err != nil {
				panic(err)
			}
			request, err := unix.NewIfreq("xlate46")
			if err != nil {
				panic(err)
			}
			request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
			if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
				panic(err)
			}
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			<-ctx.Done()
			cancel()
			_ = unix.Close(fd)
			os.Exit(0)
		case "show":
			data, err := os.ReadFile(os.Getenv("DISCOVERY_TRANSLATION_SERVICE"))
			if err != nil {
				panic(err)
			}
			fmt.Print(string(data))
			os.Exit(0)
		case "observe":
			if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
				panic(err)
			}
			data, err := os.ReadFile(os.Args[2])
			if err != nil {
				panic(err)
			}
			var settings config.Translators
			if err := json.Unmarshal(data, &settings); err != nil {
				panic(err)
			}
			s, err := New(&settings, []config.LAN{{Interface: "lan0"}})
			if err != nil {
				panic(err)
			}
			value := s.observer.observe(context.Background(), s.settings, s.spaces, s.lans)
			fmt.Print(len(value.maps))
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestReadinessWithImmutableFilesRealProcessAndKernel(t *testing.T) {
	if os.Getenv("DISCOVERY_TRANSLATION_LAB") == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", self, "-test.run=^TestReadinessWithImmutableFilesRealProcessAndKernel$", "-test.timeout=20s", "-test.v")
		cmd.Env = append(os.Environ(), "DISCOVERY_TRANSLATION_LAB=1", "GORACE=atexit_sleep_ms=0")
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated readiness lab: %v\n%s", err, data)
		}
		return
	}
	directory, err := os.MkdirTemp("", "translation-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "translator.test")
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	if err := errors.Join(copyErr, in.Close(), out.Close()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	run := func(args ...string) {
		t.Helper()
		if data, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("kernel fixture: %v: %s", err, data)
		}
	}
	run("ip", "tuntap", "add", "dev", "xlate46", "mode", "tun")
	run("ip", "link", "set", "xlate46", "up")
	run("ip", "address", "add", "198.51.100.1/32", "dev", "xlate46")
	run("ip", "address", "add", "2001:db8:46:ffff::1/128", "dev", "xlate46", "nodad")
	run("ip", "route", "add", "198.51.100.0/24", "dev", "xlate46")
	run("ip", "-6", "route", "add", "2001:db8:46::/96", "dev", "xlate46")
	run("ip", "link", "add", "lan0", "type", "dummy")
	run("ip", "link", "set", "lan0", "up")
	run("ip", "address", "add", "2001:db8:1::1/64", "dev", "lan0", "nodad")
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	s := fixture(t)
	s.settings.IP = []string{ip}
	s.settings.Systemctl = []string{binary}
	s.settings.NAT64 = nil
	immutable := filepath.Join(directory, "immutable")
	if err := os.Mkdir(immutable, 0755); err != nil {
		t.Fatal(err)
	}
	profile := s.settings.NAT46
	profile.Binary = binary
	profile.Config = filepath.Join(immutable, "translator46.conf")
	if err := os.WriteFile(profile.Config, []byte(config46), 0444); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "settings.json")
	data, err := json.Marshal(s.settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0444); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(immutable, immutable, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(immutable, 0) })
	if err := unix.Mount("", immutable, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	translator := exec.CommandContext(ctx, binary, "--nodetach", "--config", profile.Config)
	var log strings.Builder
	translator.Stdout, translator.Stderr = &log, &log
	if err := translator.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = translator.Process.Signal(syscall.SIGTERM)
		if err := translator.Wait(); err != nil {
			t.Errorf("translator fixture: %v: %s", err, log.String())
		}
	}()
	servicePath := filepath.Join(directory, "service")
	serviceText := "ActiveState=active\nSubState=running\nMainPID=" + strconv.Itoa(translator.Process.Pid) + "\nInvocationID=" + strings.Repeat("a", 32) + "\n"
	if err := os.WriteFile(servicePath, []byte(serviceText), 0444); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DISCOVERY_TRANSLATION_SERVICE", servicePath)
	observe := func() int {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, "observe", configPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("unprivileged sampler: %v: %s", err, data)
		}
		maps, err := strconv.Atoi(string(data))
		if err != nil {
			t.Fatal(err, string(data))
		}
		return maps
	}
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if observe() == 1 {
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real TUN/process/immutable profile never became ready")
	}
	run("ip", "-6", "route", "add", "blackhole", "2001:db8:1::42/128")
	if observe() != 0 {
		t.Fatal("blackhole target route did not withdraw mapping")
	}
	run("ip", "-6", "route", "del", "blackhole", "2001:db8:1::42/128")
	if observe() != 1 {
		t.Fatal("restored route did not recover existing map")
	}
	if err := unix.Mount("", immutable, "", unix.MS_BIND|unix.MS_REMOUNT, ""); err != nil {
		t.Fatal(err)
	}
	if observe() != 0 {
		t.Fatal("writable profile remained ready")
	}
	if err := unix.Mount("", immutable, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	if observe() != 1 {
		t.Fatal("immutable profile failed to recover")
	}
	run("ip", "link", "set", "xlate46", "down")
	if observe() != 0 {
		t.Fatal("down TUN remained ready")
	}
}
