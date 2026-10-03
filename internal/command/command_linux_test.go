package command

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCommandProcess(t *testing.T) {
	if os.Getenv("DISCOVERY_COMMAND_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "literal":
		fmt.Print("$(false)`false`\n")
	case "overflow":
		fmt.Print(strings.Repeat("x", 8192))
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestCommandProcess$", "--", "sleep")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("DISCOVERY_COMMAND_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(3)
		}
		time.Sleep(10 * time.Second)
	case "sleep":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func TestCommandBoundsOutputDeadlineAndDescendants(t *testing.T) {
	t.Setenv("DISCOVERY_COMMAND_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := func(mode string) []string { return []string{executable, "-test.run=^TestCommandProcess$", "--", mode} }
	data, err := Run(context.Background(), argv("literal"), 3*time.Second, 1024)
	if err != nil || string(data) != "$(false)`false`\n" {
		t.Fatal(string(data), err)
	}
	if data, err := Run(context.Background(), argv("overflow"), 3*time.Second, 1024); err == nil || data != nil {
		t.Fatal("oversized stdout accepted")
	}
	pidfile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("DISCOVERY_COMMAND_PID", pidfile)
	started := time.Now()
	if _, err := Run(context.Background(), argv("descendant"), 500*time.Millisecond, 1024); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("process group did not obey deadline", err)
	}
	data, err = os.ReadFile(pidfile)
	if err != nil {
		t.Fatal("descendant never started", err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	// A killed orphan can remain a zombie until the host reaps it. It must not
	// remain live or retain the inherited stdout descriptor.
	deadline := time.Now().Add(time.Second)
	for {
		status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if os.IsNotExist(err) || err == nil && strings.Contains(string(status), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command descendant survived cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, invalid := range []struct {
		argv     []string
		duration time.Duration
		limit    int
	}{
		{nil, time.Second, 1}, {[]string{"relative"}, time.Second, 1}, {argv("literal"), 4 * time.Second, 1}, {argv("literal"), time.Second, 0},
	} {
		if _, err := Run(context.Background(), invalid.argv, invalid.duration, invalid.limit); err == nil {
			t.Fatal("unbounded command accepted")
		}
	}
}
