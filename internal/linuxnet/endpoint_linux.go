package linuxnet

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ErrDatagramRejected marks invalid local traffic that does not revoke a socket.
var ErrDatagramRejected = errors.New("pod datagram rejected")

// Description is the existing broker socket handoff format.
type Description struct {
	Index     int          `json:"index"`
	Family    int          `json:"family"`
	Addresses []netip.Addr `json:"addresses"`
}

// Endpoint owns an adopted pod socket without entering its namespace.
type Endpoint struct {
	Description Description
	Socket      *net.UDPConn
	source      netip.Addr
	group       netip.Addr
	control     []byte
}

// Adopt verifies a multicast-bound UDP descriptor and takes file ownership.
func Adopt(file *os.File, description Description) (_ *Endpoint, err error) {
	defer func() { err = errors.Join(err, file.Close()) }()
	if description.Index < 1 || (description.Family != 4 && description.Family != 6) || len(description.Addresses) < 1 || len(description.Addresses) > 16 {
		return nil, errors.New("invalid socket description")
	}
	endpoint := &Endpoint{Description: description}
	endpoint.group = netip.MustParseAddr("224.0.0.251")
	if description.Family == 6 {
		endpoint.group = netip.MustParseAddr("ff02::fb")
	}
	for _, address := range description.Addresses {
		if !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsMulticast() || address.IsUnspecified() || address.IsLoopback() {
			return nil, errors.New("unusable socket address")
		}
		if !endpoint.source.IsValid() && ((description.Family == 4 && address.Is4()) || (description.Family == 6 && address.Is6())) {
			endpoint.source = address
		}
	}
	if !endpoint.source.IsValid() {
		return nil, errors.New("missing socket family address")
	}
	fd := int(file.Fd())
	for option, expected := range map[int]int{unix.SO_TYPE: unix.SOCK_DGRAM, unix.SO_PROTOCOL: unix.IPPROTO_UDP} {
		value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
		if err != nil || value != expected {
			return nil, errors.New("handoff descriptor is not UDP")
		}
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	valid := false
	switch value := address.(type) {
	case *unix.SockaddrInet4:
		valid = description.Family == 4 && value.Port == 5353 && netip.AddrFrom4(value.Addr) == endpoint.group
	case *unix.SockaddrInet6:
		valid = description.Family == 6 && value.Port == 5353 && value.ZoneId == uint32(description.Index) && netip.AddrFrom16(value.Addr) == endpoint.group
	}
	if !valid {
		return nil, errors.New("socket is not bound to its described multicast group")
	}
	connection, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		return nil, errors.Join(errors.New("handoff is not a UDP connection"), connection.Close())
	}
	endpoint.Socket = udp
	source := net.IP(endpoint.source.AsSlice())
	if description.Family == 4 {
		endpoint.control = (&ipv4.ControlMessage{Src: source, IfIndex: description.Index}).Marshal()
	} else {
		endpoint.control = (&ipv6.ControlMessage{Src: source, IfIndex: description.Index}).Marshal()
	}
	return endpoint, nil
}

// Receive admits only this pod's sources, multicast group, interface and hop 255.
func (e *Endpoint) Receive() ([]byte, *net.UDPAddr, error) {
	buffer, control := make([]byte, 9000), make([]byte, 256)
	n, oobn, flags, peer, err := e.Socket.ReadMsgUDP(buffer, control)
	if err != nil {
		return nil, nil, err
	}
	if n == 0 && peer == nil {
		return nil, nil, io.EOF
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < 12 || n > 9000 || peer == nil || peer.Port < 1 {
		return nil, nil, errors.Join(ErrDatagramRejected, errors.New("invalid or truncated pod datagram"))
	}
	source, ok := netip.AddrFromSlice(peer.IP)
	if !ok || !slices.Contains(e.Description.Addresses, source.Unmap()) {
		return nil, nil, errors.Join(ErrDatagramRejected, errors.New("datagram source is outside this pod"))
	}
	index, hop := 0, 0
	var destination net.IP
	if e.Description.Family == 4 {
		var cm ipv4.ControlMessage
		if err := cm.Parse(control[:oobn]); err != nil {
			return nil, nil, errors.Join(ErrDatagramRejected, err)
		}
		index, hop, destination = cm.IfIndex, cm.TTL, cm.Dst
	} else {
		var cm ipv6.ControlMessage
		if err := cm.Parse(control[:oobn]); err != nil {
			return nil, nil, errors.Join(ErrDatagramRejected, err)
		}
		index, hop, destination = cm.IfIndex, cm.HopLimit, cm.Dst
	}
	dst, ok := netip.AddrFromSlice(destination)
	if !ok || dst.Unmap() != e.group || index != e.Description.Index || hop != 255 {
		return nil, nil, errors.Join(ErrDatagramRejected, errors.New("pod datagram interface, destination or hop rejected"))
	}
	return buffer[:n], peer, nil
}

// Send permits only DNS replies to this pod or its local multicast group.
func (e *Endpoint) Send(wire []byte, peer *net.UDPAddr, multicast bool) error {
	if len(wire) < 12 || len(wire) > 8952 || binary.BigEndian.Uint16(wire[2:4])&0x8000 == 0 || peer == nil || peer.Port < 1 || peer.Port > 65535 {
		return errors.New("answer-only pod reply required")
	}
	address, ok := netip.AddrFromSlice(peer.IP)
	if !ok || !slices.Contains(e.Description.Addresses, address.Unmap()) {
		return errors.New("reply peer is outside this pod")
	}
	target := peer
	if multicast {
		target = &net.UDPAddr{IP: net.IP(e.group.AsSlice()), Port: 5353}
		if e.Description.Family == 6 {
			target.Zone = strconv.Itoa(e.Description.Index)
		}
	}
	n, _, err := e.Socket.WriteMsgUDP(wire, e.control, target)
	if err != nil {
		return err
	}
	if n != len(wire) {
		return io.ErrShortWrite
	}
	return nil
}

// Close releases the worker's duplicate; broker ownership revokes shared state.
func (e *Endpoint) Close() error { return e.Socket.Close() }
