package observation

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ipv4Envelope(data []byte, packet Packet) []byte {
	wire := make([]byte, 20+len(data))
	wire[0], wire[8], wire[9] = 0x45, byte(packet.HopLimit), 17
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)))
	copy(wire[12:16], packet.Source.AsSlice())
	copy(wire[16:20], packet.Destination.AsSlice())
	binary.BigEndian.PutUint16(wire[10:12], checksum(wire[:20]))
	copy(wire[20:], data)
	return wire
}

func TestRawUDPChecksumSizeAndMetadataAdmission(t *testing.T) {
	for _, family := range []int{4, 6} {
		packet := Packet{Family: family, HopLimit: 255, Source: netip.MustParseAddr("192.0.2.42"), Destination: netip.MustParseAddr("224.0.0.251")}
		if family == 6 {
			packet.Source, packet.Destination = netip.MustParseAddr("2001:db8:1::42"), netip.MustParseAddr("ff02::fb")
		}
		data, err := Datagram(make([]byte, 13), packet.Source, packet.Destination)
		if err != nil {
			t.Fatal(err)
		}
		if family == 6 {
			if _, err := UDP(data, packet); err == nil {
				t.Fatal("missing IPv6 checksum accepted")
			}
			binary.BigEndian.PutUint16(data[6:8], checksum(append(pseudoHeader(packet.Source, packet.Destination, len(data)), data...)))
		} else {
			data = ipv4Envelope(data, packet)
		}
		value, err := UDP(data, packet)
		if err != nil || len(value.Wire) != 13 || value.SourcePort != 5353 || value.DestinationPort != 5353 {
			t.Fatal(value, err)
		}
		for _, corrupt := range []func([]byte){
			func(wire []byte) { wire[len(wire)-1] ^= 1 },
			func(wire []byte) {
				if family == 4 {
					wire[2] ^= 1
				} else {
					wire[4] ^= 1
				}
			},
		} {
			bad := append([]byte(nil), data...)
			corrupt(bad)
			if _, err := UDP(bad, packet); err == nil {
				t.Fatal("corrupt raw packet accepted")
			}
		}
		if family == 4 {
			noCheck := append([]byte(nil), data...)
			noCheck[26], noCheck[27] = 0, 0
			if _, err := UDP(noCheck, packet); err != nil {
				t.Fatal("IPv4 UDP checksum is optional", err)
			}
			fragment := append([]byte(nil), data...)
			fragment[6], fragment[10], fragment[11] = 0x20, 0, 0
			binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:20]))
			if _, err := UDP(fragment, packet); err == nil {
				t.Fatal("unreassembled IPv4 fragment accepted")
			}
			packet.Source = netip.MustParseAddr("192.0.2.43")
			if _, err := UDP(data, packet); err == nil {
				t.Fatal("header and receive metadata mismatch accepted")
			}
		}
	}
}
