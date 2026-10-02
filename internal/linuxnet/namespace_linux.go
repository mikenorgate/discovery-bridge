// Package linuxnet opens pod sockets while retaining Linux namespace identity.
package linuxnet

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Namespace pins a process and its network namespace against PID reuse.
type Namespace struct {
	mu      sync.Mutex
	proc    string
	pid     int
	process *os.File
	network *os.File
	start   string
}

func opened(fd int, err error, name string) (*os.File, error) {
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func same(left, right *os.File) (bool, error) {
	a, err := left.Stat()
	if err != nil {
		return false, err
	}
	b, err := right.Stat()
	if err != nil {
		return false, err
	}
	return os.SameFile(a, b), nil
}

func startTime(process *os.File) (string, error) {
	fd, err := unix.Openat(int(process.Fd()), "stat", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	file, err := opened(fd, err, "process stat")
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return "", err
	}
	index := strings.LastIndexByte(string(data), ')')
	if len(data) > 4096 || index < 0 {
		return "", errors.New("invalid bounded process identity")
	}
	fields := strings.Fields(string(data[index+1:]))
	if len(fields) < 20 {
		return "", errors.New("incomplete process identity")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}

// Open verifies and pins a non-host process network namespace.
func Open(proc string, pid int) (*Namespace, error) {
	if !filepath.IsAbs(proc) || pid <= 1 {
		return nil, errors.New("absolute proc mount and sandbox PID required")
	}
	path := filepath.Join(proc, strconv.Itoa(pid))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	process, err := opened(fd, err, "sandbox process")
	if err != nil {
		return nil, err
	}
	ns := &Namespace{proc: proc, pid: pid, process: process}
	fail := func(err error) (*Namespace, error) { return nil, errors.Join(err, ns.Close()) }
	ns.start, err = startTime(process)
	if err != nil {
		return fail(err)
	}
	fd, err = unix.Openat(int(process.Fd()), "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	ns.network, err = opened(fd, err, "sandbox namespace")
	if err != nil {
		return fail(err)
	}
	for _, path := range []string{"/proc/thread-self/ns/net", filepath.Join(proc, "1/ns/net")} {
		candidate, err := os.Open(path)
		if err != nil {
			return fail(err)
		}
		match, statErr := same(candidate, ns.network)
		closeErr := candidate.Close()
		if err := errors.Join(statErr, closeErr); err != nil {
			return fail(err)
		}
		if match {
			return fail(errors.New("host or broker network namespace rejected"))
		}
	}
	if err := ns.verify(); err != nil {
		return fail(err)
	}
	return ns, nil
}

func (n *Namespace) verify() (err error) {
	if n.process == nil || n.network == nil {
		return errors.New("closed network namespace")
	}
	fd, err := unix.Open(filepath.Join(n.proc, strconv.Itoa(n.pid)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	current, err := opened(fd, err, "current sandbox process")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, current.Close()) }()
	match, err := same(current, n.process)
	if err != nil {
		return err
	}
	start, err := startTime(current)
	if err != nil {
		return err
	}
	if !match || start != n.start {
		return errors.New("sandbox process identity changed")
	}
	fd, err = unix.Openat(int(current.Fd()), "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	network, err := opened(fd, err, "current sandbox namespace")
	if err != nil {
		return err
	}
	match, statErr := same(network, n.network)
	closeErr := network.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return err
	}
	if !match {
		return errors.New("sandbox network namespace changed")
	}
	return nil
}

// With performs direct namespace operations on a locked OS thread, then restores.
// fn must use direct syscalls; it must not delegate namespace work to goroutines.
func (n *Namespace) With(fn func() error) (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.verify(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	home, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, home.Close()) }()
	if err := unix.Setns(int(n.network.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter namespace: %w", err)
	}
	defer func() {
		if restoreErr := unix.Setns(int(home.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			// Continuing or unlocking would expose a pod namespace to the runtime.
			os.Exit(70)
		}
		err = errors.Join(err, n.verify())
	}()
	return fn()
}

// Socket opens an mDNS UDP socket bound to the configured pod interface.
func (n *Namespace) Socket(iface string, family int) (*os.File, error) {
	if iface == "" || len(iface) >= unix.IFNAMSIZ || strings.ContainsAny(iface, "/\x00\n") || (family != 4 && family != 6) {
		return nil, errors.New("valid interface and IP family required")
	}
	var result *os.File
	err := n.With(func() error {
		domain := unix.AF_INET
		if family == 6 {
			domain = unix.AF_INET6
		}
		fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		file, err := opened(fd, err, "pod mDNS socket")
		if err != nil {
			return err
		}
		result = file
		for _, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, 1); err != nil {
				return err
			}
		}
		if err := unix.BindToDevice(fd, iface); err != nil {
			return err
		}
		request, err := unix.NewIfreq(iface)
		if err != nil {
			return err
		}
		if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, request); err != nil {
			return err
		}
		index := request.Uint32()
		if index == 0 || index > math.MaxInt32 {
			return errors.New("invalid pod interface index")
		}
		if family == 4 {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
				return err
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1); err != nil {
				return err
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 255); err != nil {
				return err
			}
			if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 5353}); err != nil {
				return err
			}
			return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &unix.IPMreqn{Multiaddr: [4]byte{224, 0, 0, 251}, Ifindex: int32(index)})
		}
		for _, option := range []int{unix.IPV6_V6ONLY, unix.IPV6_RECVPKTINFO, unix.IPV6_RECVHOPLIMIT} {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, option, 1); err != nil {
				return err
			}
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet6{Port: 5353}); err != nil {
			return err
		}
		return unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &unix.IPv6Mreq{Multiaddr: [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}, Interface: index})
	})
	if err != nil && result != nil {
		return nil, errors.Join(err, result.Close())
	}
	return result, err
}

// Close releases the pinned namespace and process descriptors.
func (n *Namespace) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var err error
	if n.network != nil {
		err = n.network.Close()
		n.network = nil
	}
	if n.process != nil {
		err = errors.Join(err, n.process.Close())
		n.process = nil
	}
	return err
}
