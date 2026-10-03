// Package command runs fixed operator-owned CLI inputs with bounded resources.
package command

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type output struct {
	data   []byte
	limit  int
	cancel context.CancelFunc
}

func (o *output) Write(data []byte) (int, error) {
	if len(data) > o.limit-len(o.data) {
		o.cancel()
		return 0, errors.New("command output limit")
	}
	o.data = append(o.data, data...)
	return len(data), nil
}

// Run bounds stdout, lifetime and process descendants without invoking a shell.
func Run(ctx context.Context, argv []string, timeout time.Duration, limit int) ([]byte, error) {
	if len(argv) < 1 || !filepath.IsAbs(argv[0]) || timeout <= 0 || timeout > 3*time.Second || limit < 1 || limit > 4_194_304 {
		return nil, errors.New("bounded absolute command required")
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(bounded, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 300 * time.Millisecond
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	}
	result := &output{limit: limit, cancel: cancel}
	cmd.Stdout = result
	err := cmd.Run()
	if cmd.Process != nil {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	if err != nil || bounded.Err() != nil {
		return nil, errors.New("read-only command unavailable")
	}
	return result.data, nil
}
