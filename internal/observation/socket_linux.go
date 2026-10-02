package observation

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ErrPacketRejected denotes malformed traffic, rather than receiver failure.
var ErrPacketRejected = errors.New("LAN packet rejected")

func rawSocket(name string, index, family int) (_ *net.IPConn, err error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if index < 1 || iface.Index != index || iface.Flags&(net.FlagUp|net.FlagMulticast) != net.FlagUp|net.FlagMulticast || (family != 4 && family != 6) {
		return nil, errors.New("raw socket requires a current multicast LAN interface")
	}
	af := unix.AF_INET
	if family == 6 {
		af = unix.AF_INET6
	}
	fd, err := unix.Socket(af, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "scoped LAN raw UDP")
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 256*1024); err != nil {
		return nil, err
	}
	if family == 6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6); err != nil {
			return nil, err
		}
	}
	connection, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	ip, ok := connection.(*net.IPConn)
	if !ok {
		return nil, errors.Join(errors.New("raw socket is not an IP connection"), connection.Close())
	}
	return ip, nil
}

func familySource(family int, addresses []netip.Addr) (netip.Addr, error) {
	var source netip.Addr
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return netip.Addr{}, errors.New("invalid local LAN address")
		}
		if address.Is4() == (family == 4) && (!source.IsValid() || source.IsLinkLocalUnicast() && !address.IsLinkLocalUnicast()) {
			source = address
		}
	}
	if !source.IsValid() {
		return source, errors.New("missing LAN address for enabled family")
	}
	return source, nil
}

func multicast(family int) netip.Addr {
	if family == 4 {
		return netip.MustParseAddr("224.0.0.251")
	}
	return netip.MustParseAddr("ff02::fb")
}

// Receiver observes raw UDP copies so Avahi retains unicast ownership of port 5353.
// Linux supplies IP reassembly before receive; checksums and scope are verified.
type Receiver struct {
	Socket        *net.IPConn
	index, family int
	generation    string
}

// OpenReceiver requires CAP_NET_RAW, an approved interface and its captured addresses.
func OpenReceiver(name string, index int, generation string, family int, addresses []netip.Addr) (_ *Receiver, err error) {
	if generation == "" || len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("bounded LAN generation and addresses required")
	}
	source, err := familySource(family, addresses)
	if err != nil {
		return nil, err
	}
	conn, err := rawSocket(name, index, family)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close())
		}
	}()
	control, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var optionErr error
	err = control.Control(func(fd uintptr) {
		if family == 4 {
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); optionErr != nil {
				return
			}
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL, 1); optionErr != nil {
				return
			}
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); optionErr != nil {
				return
			}
			optionErr = unix.SetsockoptIPMreqn(int(fd), unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &unix.IPMreqn{Multiaddr: multicast(4).As4(), Address: source.As4(), Ifindex: int32(index)})
		} else {
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); optionErr != nil {
				return
			}
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1); optionErr != nil {
				return
			}
			optionErr = unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &unix.IPv6Mreq{Multiaddr: multicast(6).As16(), Interface: uint32(index)})
		}
	})
	if err = errors.Join(err, optionErr); err != nil {
		return nil, err
	}
	return &Receiver{Socket: conn, index: index, family: family, generation: generation}, nil
}

// Receive keeps kernel destination, interface and hop metadata for later admission.
// Close interrupts a pending receive when the collector's topology epoch ends.
func (r *Receiver) Receive() (Packet, error) {
	buffer, ancillary := make([]byte, 9100), make([]byte, 256)
	n, oobn, flags, peer, err := r.Socket.ReadMsgIP(buffer, ancillary)
	if err != nil {
		return Packet{}, err
	}
	if peer == nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return Packet{}, errors.Join(ErrPacketRejected, errors.New("raw receive data or metadata truncated"))
	}
	packet := Packet{Family: r.family, Generation: r.generation}
	var destination net.IP
	if r.family == 4 {
		var cm ipv4.ControlMessage
		if err := cm.Parse(ancillary[:oobn]); err != nil {
			return Packet{}, errors.Join(ErrPacketRejected, err)
		}
		packet.Interface, packet.HopLimit, destination = cm.IfIndex, cm.TTL, cm.Dst
	} else {
		var cm ipv6.ControlMessage
		if err := cm.Parse(ancillary[:oobn]); err != nil {
			return Packet{}, errors.Join(ErrPacketRejected, err)
		}
		packet.Interface, packet.HopLimit, destination = cm.IfIndex, cm.HopLimit, cm.Dst
	}
	src, sourceOK := netip.AddrFromSlice(peer.IP)
	dst, destinationOK := netip.AddrFromSlice(destination)
	if !sourceOK || !destinationOK || packet.Interface != r.index || packet.HopLimit < 1 {
		return Packet{}, errors.Join(ErrPacketRejected, errors.New("missing or mismatched raw receive metadata"))
	}
	packet.Source, packet.Destination = src.Unmap(), dst.Unmap()
	packet, err = UDP(buffer[:n], packet)
	if err != nil {
		return Packet{}, errors.Join(ErrPacketRejected, err)
	}
	return packet, nil
}

// Close releases the collector's observation socket.
func (r *Receiver) Close() error { return r.Socket.Close() }

// Sender emits only fresh discovery questions or authorized TTL-zero goodbyes.
// Raw UDP avoids binding Avahi's port and permits kernel IP fragmentation.
type Sender struct {
	socket        *net.IPConn
	source, group netip.Addr
	index, family int
	control       []byte
}

// OpenSender creates a source- and interface-bound multicast transmitter.
func OpenSender(name string, index, family int, addresses []netip.Addr) (_ *Sender, err error) {
	source, err := familySource(family, addresses)
	if err != nil {
		return nil, err
	}
	conn, err := rawSocket(name, index, family)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close())
		}
	}()
	control, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var optionErr error
	err = control.Control(func(fd uintptr) {
		if family == 4 {
			if optionErr = unix.Bind(int(fd), &unix.SockaddrInet4{Addr: source.As4()}); optionErr != nil {
				return
			}
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 255); optionErr != nil {
				return
			}
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
		} else {
			if optionErr = unix.Bind(int(fd), &unix.SockaddrInet6{Addr: source.As16(), ZoneId: uint32(index)}); optionErr != nil {
				return
			}
			if optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); optionErr != nil {
				return
			}
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT)
		}
	})
	if err = errors.Join(err, optionErr); err != nil {
		return nil, err
	}
	s := &Sender{socket: conn, source: source, group: multicast(family), index: index, family: family}
	if family == 4 {
		s.control = (&ipv4.ControlMessage{Src: net.IP(source.AsSlice()), IfIndex: index}).Marshal()
	} else {
		s.control = (&ipv6.ControlMessage{Src: net.IP(source.AsSlice()), IfIndex: index}).Marshal()
	}
	return s, nil
}

func (s *Sender) send(ctx context.Context, wire []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := s.socket.SetWriteDeadline(deadline); err != nil {
		return err
	}
	data, err := Datagram(wire, s.source, s.group)
	if err != nil {
		return err
	}
	target := &net.IPAddr{IP: net.IP(s.group.AsSlice())}
	if s.family == 6 {
		target.Zone = strconv.Itoa(s.index)
	}
	n, _, err := s.socket.WriteMsgIP(data, s.control, target)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Questions requests fresh evidence using names and types only, never client sections.
func (s *Sender) Questions(ctx context.Context, name string, types []uint16) error {
	if !catalog.LocalName(name) || len(types) == 0 || len(types) > 5 || slices.ContainsFunc(types, func(kind uint16) bool { return !Supported(kind) }) {
		return errors.New("invalid fresh mDNS question")
	}
	message := new(dns.Msg)
	for _, kind := range types {
		message.Question = append(message.Question, dns.Question{Name: name, Qtype: kind, Qclass: dns.ClassINET})
	}
	wire, err := message.Pack()
	if err != nil || len(wire) > 1232 {
		return errors.New("fresh question packet exceeds budget")
	}
	return s.send(ctx, wire)
}

// Goodbyes withdraws previously admitted publications after Avahi has reset them.
// Avahi 0.8 can suppress duplicate-interface goodbyes; explicit scoped packets
// retain the existing behavior. The independent publisher supplies ownership.
func (s *Sender) Goodbyes(ctx context.Context, answers []catalog.Answer) error {
	if len(answers) > catalog.MaxRecords {
		return errors.New("goodbye record budget exceeded")
	}
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}}
	var packets [][]byte
	for _, answer := range answers {
		if answer.RR == nil || !Supported(answer.RR.Header().Rrtype) || !catalog.LocalName(answer.RR.Header().Name) {
			return errors.New("invalid admitted goodbye record")
		}
		rr := dns.Copy(answer.RR)
		rr.Header().Ttl, rr.Header().Class = 0, dns.ClassINET
		if answer.Unique {
			rr.Header().Class |= 0x8000
		}
		message.Answer = append(message.Answer, rr)
		wire, err := message.Pack()
		if err != nil {
			return err
		}
		if len(wire) > 1232 && len(message.Answer) > 1 {
			message.Answer = message.Answer[:len(message.Answer)-1]
			previous, err := message.Pack()
			if err != nil || len(previous) > 8952 {
				return errors.New("goodbye packet exceeds size budget")
			}
			packets = append(packets, previous)
			message.Answer = []dns.RR{rr}
		}
	}
	if len(message.Answer) > 0 {
		wire, err := message.Pack()
		if err != nil || len(wire) > 8952 {
			return errors.New("goodbye packet exceeds size budget")
		}
		packets = append(packets, wire)
	}
	if len(packets) > 256 {
		return errors.New("goodbye packet count exceeds budget")
	}
	for _, wire := range packets {
		if err := s.send(ctx, wire); err != nil {
			return err
		}
	}
	return nil
}

// Close releases the multicast transmitter.
func (s *Sender) Close() error { return s.socket.Close() }

// LinkMonitor invalidates the captured topology on any link or address notification.
type LinkMonitor struct{ socket *os.File }

// OpenMonitor subscribes to kernel link and IPv4/IPv6 address changes.
func OpenMonitor() (_ *LinkMonitor, err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "LAN topology notifications")
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR}); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &LinkMonitor{socket: file}, nil
}

// Wait returns after one notification or loss; both require a fresh topology epoch.
func (m *LinkMonitor) Wait() error { _, err := m.socket.Read(make([]byte, 65536)); return err }

// Close interrupts a pending notification wait.
func (m *LinkMonitor) Close() error { return m.socket.Close() }
