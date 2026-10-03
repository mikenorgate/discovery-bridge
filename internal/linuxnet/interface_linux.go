package linuxnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// Interface is a verified namespace interface, including local IPv6 addresses.
type Interface struct {
	Index     int          `json:"index"`
	Addresses []netip.Addr `json:"addresses"`
}

// CurrentInterface captures an up multicast interface in the caller's namespace.
// Router processes use it directly; broker admission uses Namespace.Inspect.
func CurrentInterface(name string) (Interface, error) { return inspectInterface(name) }

// Inspect verifies direct Linux interface state against the API/CRI addresses.
func (n *Namespace) Inspect(name string, expected []netip.Addr) (result Interface, err error) {
	err = n.With(func() error {
		var err error
		result, err = inspectInterface(name)
		if err != nil {
			return err
		}
		actual := make([]netip.Addr, 0, len(result.Addresses))
		for _, address := range result.Addresses {
			if !address.IsLinkLocalUnicast() {
				actual = append(actual, address)
			}
		}
		wanted := slices.Clone(expected)
		slices.SortFunc(wanted, func(a, b netip.Addr) int { return a.Compare(b) })
		if !slices.Equal(actual, wanted) {
			return errors.New("API, runtime and interface addresses differ")
		}
		return nil
	})
	return result, err
}

func inspectInterface(name string) (result Interface, err error) {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return result, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, request); err != nil {
		return result, err
	}
	result.Index = int(request.Uint32())
	if result.Index < 1 {
		return result, errors.New("invalid interface index")
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return result, err
	}
	if request.Uint16()&(unix.IFF_UP|unix.IFF_MULTICAST) != unix.IFF_UP|unix.IFF_MULTICAST {
		return result, errors.New("interface must be up and support multicast")
	}
	netlink, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unix.Close(netlink)) }()
	if err := unix.SetsockoptTimeval(netlink, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return result, err
	}
	if err := unix.Bind(netlink, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, err
	}
	query := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfAddrmsg)
	binary.NativeEndian.PutUint32(query[0:4], uint32(len(query)))
	binary.NativeEndian.PutUint16(query[4:6], unix.RTM_GETADDR)
	binary.NativeEndian.PutUint16(query[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(query[8:12], 1)
	if err := unix.Sendto(netlink, query, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, err
	}
	buffer := make([]byte, 65536)
	budget := 65536
	for {
		n, _, flags, peer, err := unix.Recvmsg(netlink, buffer, nil, 0)
		if err != nil {
			return result, err
		}
		kernel, ok := peer.(*unix.SockaddrNetlink)
		budget -= n
		if !ok || kernel.Pid != 0 || budget < 0 || flags&unix.MSG_TRUNC != 0 {
			return result, errors.New("invalid or excessive netlink response")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return result, err
		}
		for _, message := range messages {
			if message.Header.Seq != 1 || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return result, errors.New("interface address dump changed")
			}
			if message.Header.Type == unix.NLMSG_DONE {
				if len(result.Addresses) == 0 || len(result.Addresses) > 16 {
					return result, errors.New("bounded interface addresses required")
				}
				slices.SortFunc(result.Addresses, func(a, b netip.Addr) int { return a.Compare(b) })
				return result, nil
			}
			if message.Header.Type != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
				return result, errors.New("unexpected netlink address message")
			}
			data := message.Data
			if int(binary.NativeEndian.Uint32(data[4:8])) != result.Index {
				continue
			}
			flags := uint32(data[2])
			attributes, err := syscall.ParseNetlinkRouteAttr(&message)
			if err != nil {
				return result, err
			}
			var primary, local []byte
			for _, a := range attributes {
				switch a.Attr.Type {
				case unix.IFA_ADDRESS:
					primary = a.Value
				case unix.IFA_LOCAL:
					local = a.Value
				case unix.IFA_FLAGS:
					if len(a.Value) != 4 {
						return result, errors.New("invalid address flags")
					}
					flags = binary.NativeEndian.Uint32(a.Value)
				}
			}
			if data[0] == unix.AF_INET && len(local) > 0 {
				primary = local
			}
			address, ok := netip.AddrFromSlice(primary)
			if !ok || flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_DEPRECATED) != 0 || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.Is4In6() {
				return result, errors.New("pod interface address is not ready")
			}
			result.Addresses = append(result.Addresses, address)
		}
	}
}

// Verify rechecks the anchored process and namespace identity.
func (n *Namespace) Verify() error { n.mu.Lock(); defer n.mu.Unlock(); return n.verify() }

// Key identifies the pinned sandbox namespace and process start time.
func (n *Namespace) Key() (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.verify(); err != nil {
		return "", err
	}
	var info unix.Stat_t
	if err := unix.Fstat(int(n.network.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%s:%d:%d", n.pid, n.start, info.Dev, info.Ino), nil
}

// Revoke shuts down shared UDP descriptions before releasing broker ownership.
func Revoke(file *os.File) error {
	err := unix.Shutdown(int(file.Fd()), unix.SHUT_RDWR)
	if errors.Is(err, unix.ENOTCONN) {
		err = nil
	}
	return errors.Join(err, file.Close())
}
