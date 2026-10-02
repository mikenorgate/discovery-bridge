package linuxnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Worker owns the broker end of a private channel and the child lifetime.
type Worker struct {
	Channel *os.File
	PID     int
	Done    <-chan error
	process *os.Process
	uid     uint32
}

// StartWorker starts one unprivileged responder on a dedicated supervisor thread.
// The thread remains locked until Wait returns, preserving Linux PDEATHSIG.
func StartWorker(ctx context.Context, binary string, args []string, uid, gid uint32, stderr io.Writer) (*Worker, error) {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) || !strings.HasPrefix(binary, "/") {
		return nil, errors.New("absolute executable and non-root worker credentials required")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	owner := os.NewFile(uintptr(fds[0]), "broker control")
	child := os.NewFile(uintptr(fds[1]), "worker control")
	type started struct {
		worker *Worker
		err    error
	}
	ready := make(chan started, 1)
	done := make(chan error, 1)
	arguments := append([]string{"worker", "--control-fd", "3", "--parent", strconv.Itoa(os.Getpid())}, args...)
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	command.ExtraFiles = []*os.File{child}
	command.Stderr = stderr
	command.Cancel = func() error { return signalWorker(command.Process, uid, syscall.SIGKILL) }
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	supervise := func() {
		// NO_NEW_PRIVS is inherited before exec and thus by every Go worker thread.
		// Exit this goroutine while locked to retire the modified supervisor thread.
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			ready <- started{err: err}
			return
		}
		// Linux checks the dying creator thread's credentials for PDEATHSIG.
		// Drop this dedicated thread before fork so it can kill its child without
		// CAP_KILL. Raw syscalls leave the other broker threads' credentials intact.
		if err := dropThreadCredentials(uid, gid); err != nil {
			ready <- started{err: err}
			return
		}
		if err := command.Start(); err != nil {
			ready <- started{err: err}
			return
		}
		ready <- started{worker: &Worker{Channel: owner, PID: command.Process.Pid, Done: done, process: command.Process, uid: uid}}
		done <- command.Wait()
		close(done)
	}
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			// Preserve the leader's root credentials for process supervisors.
			// Hold it until a separate locked thread owns the worker lifetime.
			locked := make(chan struct{})
			go func() {
				runtime.LockOSThread()
				close(locked)
				supervise()
			}()
			<-locked
			runtime.UnlockOSThread()
			return
		}
		supervise()
	}()
	result := <-ready
	closeErr := child.Close()
	if result.err != nil {
		return nil, errors.Join(result.err, closeErr, owner.Close())
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, result.worker.Close())
	}
	return result.worker, nil
}

func dropThreadCredentials(uid, gid uint32) error {
	if _, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
		return errno
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); errno != 0 {
		return errno
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); errno != 0 {
		return errno
	}
	return nil
}

// Close revokes the channel and kills the worker, including a stopped child.
func (w *Worker) Close() error {
	channelErr := w.Channel.Close()
	if errors.Is(channelErr, os.ErrClosed) {
		channelErr = nil
	}
	err := w.Signal(syscall.SIGKILL)
	if errors.Is(err, os.ErrProcessDone) {
		err = nil
	}
	return errors.Join(channelErr, err)
}

// Signal uses the worker's UID on a dedicated thread, requiring no CAP_KILL.
// The saved root identity is restored before that temporary thread is retired.
func (w *Worker) Signal(signal syscall.Signal) error { return signalWorker(w.process, w.uid, signal) }

func signalWorker(process *os.Process, uid uint32, signal syscall.Signal) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Raw setresuid affects this locked thread, unlike Go's process-wide wrapper.
		_, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), uintptr(uid), ^uintptr(0))
		if errno != 0 {
			result <- errno
			return
		}
		err := process.Signal(signal) // Uses Go's anchored process handle when available.
		_, _, errno = unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), 0, ^uintptr(0))
		if errno != 0 {
			os.Exit(70)
		}
		result <- err
		// Returning while locked retires the thread that changed credentials.
	}()
	return <-result
}

// CheckWorkerConfinement verifies the broker established process confinement.
func CheckWorkerConfinement(parent int) error {
	if parent < 1 || os.Getppid() != parent || os.Geteuid() == 0 || os.Getegid() == 0 {
		return errors.New("invalid worker parent or credentials")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.Join(err, errors.New("worker retains supplementary groups"))
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	values := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	for _, key := range []string{"Uid", "Gid"} {
		ids := strings.Fields(values[key])
		if len(ids) != 4 {
			return fmt.Errorf("worker confinement rejected: %s", key)
		}
		for _, id := range ids {
			if id == "0" || id != ids[0] {
				return fmt.Errorf("worker confinement rejected: %s", key)
			}
		}
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapAmb", "CapInh"} {
		value, err := strconv.ParseUint(values[key], 16, 64)
		if err != nil || value != 0 {
			return fmt.Errorf("worker confinement rejected: %s", key)
		}
	}
	if values["NoNewPrivs"] != "1" {
		return errors.New("worker requires inherited NO_NEW_PRIVS")
	}
	return nil
}
