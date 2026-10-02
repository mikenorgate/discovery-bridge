package observation

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

func checksum(data []byte) uint16 {
	var total uint32
	for len(data) >= 2 {
		total += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		total += uint32(data[0]) << 8
	}
	for total>>16 != 0 {
		total = total&0xffff + total>>16
	}
	return ^uint16(total)
}

func pseudoHeader(source, destination netip.Addr, size int) []byte {
	value := append(source.AsSlice(), destination.AsSlice()...)
	if source.Is4() {
		value = append(value, 0, 17, byte(size>>8), byte(size))
	} else {
		value = binary.BigEndian.AppendUint32(value, uint32(size))
		value = append(value, 0, 0, 0, 17)
	}
	return value
}

// UDP verifies a kernel-reassembled raw datagram and retains its receive metadata.
// IPv4 includes its IP header; Linux raw IPv6 starts at the UDP header.
func UDP(data []byte, packet Packet) (Packet, error) {
	src, dst := packet.Source, packet.Destination
	if !src.IsValid() || !dst.IsValid() || src.Zone() != "" || dst.Zone() != "" || src.Is4In6() || dst.Is4In6() || (packet.Family != 4 && packet.Family != 6) || src.Is4() != (packet.Family == 4) || dst.Is4() != src.Is4() {
		return Packet{}, errors.New("raw UDP address family mismatch")
	}
	if packet.Family == 4 {
		if len(data) < 20 || data[0]>>4 != 4 {
			return Packet{}, errors.New("invalid IPv4 header")
		}
		size := int(data[0]&15) * 4
		if size < 20 || size > len(data) || int(binary.BigEndian.Uint16(data[2:4])) != len(data) || data[9] != 17 || checksum(data[:size]) != 0 || binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 {
			return Packet{}, errors.New("invalid IPv4 checksum, size or reassembly")
		}
		if netip.AddrFrom4([4]byte(data[12:16])) != src || netip.AddrFrom4([4]byte(data[16:20])) != dst || int(data[8]) != packet.HopLimit {
			return Packet{}, errors.New("IPv4 header and kernel metadata differ")
		}
		data = data[size:]
	}
	if len(data) < 20 || len(data) > 8960 || int(binary.BigEndian.Uint16(data[4:6])) != len(data) {
		return Packet{}, errors.New("invalid raw UDP size")
	}
	check := binary.BigEndian.Uint16(data[6:8])
	if packet.Family == 6 && check == 0 {
		return Packet{}, errors.New("IPv6 UDP checksum required")
	}
	if check != 0 && checksum(append(pseudoHeader(src, dst, len(data)), data...)) != 0 {
		return Packet{}, errors.New("invalid UDP checksum")
	}
	packet.SourcePort, packet.DestinationPort = int(binary.BigEndian.Uint16(data[:2])), int(binary.BigEndian.Uint16(data[2:4]))
	packet.Wire = data[8:]
	return packet, nil
}

// Datagram constructs a source-port-5353 UDP payload without binding that port.
// The IPv6 checksum is inserted by the kernel's IPV6_CHECKSUM socket option.
func Datagram(wire []byte, source, destination netip.Addr) ([]byte, error) {
	if len(wire) < 12 || len(wire) > 8952 || !source.IsValid() || !destination.IsValid() || source.Zone() != "" || destination.Zone() != "" || source.Is4In6() || destination.Is4In6() || source.Is4() != destination.Is4() {
		return nil, errors.New("invalid outgoing raw UDP size or address family")
	}
	data := make([]byte, len(wire)+8)
	binary.BigEndian.PutUint16(data[:2], 5353)
	binary.BigEndian.PutUint16(data[2:4], 5353)
	binary.BigEndian.PutUint16(data[4:6], uint16(len(data)))
	copy(data[8:], wire)
	if source.Is4() {
		check := checksum(append(pseudoHeader(source, destination, len(data)), data...))
		if check == 0 {
			check = 0xffff
		}
		binary.BigEndian.PutUint16(data[6:8], check)
	}
	return data, nil
}
