//go:build integration && linux

package linuxnet_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/discovery-bridge/internal/linuxnet"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		flags := flag.NewFlagSet("worker", flag.ExitOnError)
		fd := flags.Int("control-fd", -1, "")
		parent := flags.Int("parent", -1, "")
		if err := flags.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		if err := linuxnet.CheckWorkerConfinement(*parent); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		// Check all runtime threads inherited the restriction before exec.
		tasks, err := filepath.Glob("/proc/self/task/*/status")
		if err != nil {
			os.Exit(1)
		}
		for _, path := range tasks {
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), "NoNewPrivs:\t1") {
				os.Exit(1)
			}
		}
		if err := linuxnet.Send(*fd, map[string]int{"pid": os.Getpid(), "uid": os.Geteuid()}, nil); err != nil {
			os.Exit(1)
		}
		for {
			if _, _, err := linuxnet.Receive(*fd); err != nil {
				os.Exit(0)
			}
		}
	}
	os.Exit(m.Run())
}

func TestWorkerBrokerHelper(t *testing.T) {
	if os.Getenv("DISCOVERY_BRIDGE_TEST_BROKER") != "1" {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// go test places its executable under a private build directory. Install
	// the worker copy as a public executable, matching packaged /usr/bin access.
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	workerBinary, err := os.CreateTemp("/tmp", "discovery-bridge-worker-*.test")
	if err != nil {
		if closeErr := source.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(workerBinary.Name()); err != nil {
			t.Error(err)
		}
	}()
	_, copyErr := io.Copy(workerBinary, source)
	modeErr := workerBinary.Chmod(0755)
	if err := errors.Join(copyErr, modeErr, workerBinary.Close(), source.Close()); err != nil {
		t.Fatal(err)
	}
	binary = workerBinary.Name()
	w, err := linuxnet.StartWorker(context.Background(), binary, nil, 65532, 65532, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	data, fds, err := linuxnet.Receive(int(w.Channel.Fd()))
	if err != nil || len(fds) != 0 {
		t.Fatal(err, fds)
	}
	if _, err := fmt.Fprintln(os.Stdout, string(data)); err != nil {
		t.Fatal(err)
	}
	// The supervisor remains alive until the outer test kills this broker.
	<-w.Done
}

func TestWorkerDiesWithBrokerEvenWhenStopped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("worker integration requires root")
	}
	for _, stopped := range []bool{false, true} {
		t.Run(strconv.FormatBool(stopped), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, binary, "-test.run=^TestWorkerBrokerHelper$")
			command.Env = append(os.Environ(), "DISCOVERY_BRIDGE_TEST_BROKER=1")
			command.Stderr = os.Stderr
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				if err := command.Wait(); err == nil {
					t.Error("broker kill unexpectedly succeeded")
				}
			}()
			reader := bufio.NewScanner(stdout)
			if !reader.Scan() {
				t.Fatal("worker did not acknowledge confinement", reader.Err())
			}
			var info struct {
				PID int `json:"pid"`
				UID int `json:"uid"`
			}
			if err := json.Unmarshal(reader.Bytes(), &info); err != nil || info.PID <= 1 || info.UID != 65532 {
				t.Fatalf("worker acknowledgement %q: %#v: %v", reader.Text(), info, err)
			}
			if stopped {
				if err := unix.Kill(info.PID, unix.SIGSTOP); err != nil {
					t.Fatal(err)
				}
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(info.PID), "stat"))
				if os.IsNotExist(err) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				_, rest, ok := strings.Cut(string(data), ") ")
				if ok && strings.HasPrefix(rest, "Z ") {
					break
				} // Orphan awaiting container init reap.
				if time.Now().After(deadline) {
					t.Fatal("worker survived broker death", string(data))
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
