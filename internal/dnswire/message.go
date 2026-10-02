// Package dnswire adds bounded framing checks around the DNS library.
package dnswire

import (
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
)

// Decode rejects excessive counts, malformed compression and trailing bytes.
func Decode(wire []byte, maxBytes, maxQuestions, maxRecords int) (*dns.Msg, error) {
	if len(wire) < 12 || len(wire) > maxBytes {
		return nil, errors.New("DNS packet size limit")
	}
	questions := int(binary.BigEndian.Uint16(wire[4:6]))
	records := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) + int(binary.BigEndian.Uint16(wire[10:12]))
	if questions > maxQuestions || records > maxRecords {
		return nil, errors.New("DNS record count limit")
	}
	offset := 12
	for range questions {
		_, next, err := dns.UnpackDomainName(wire, offset)
		if err != nil || next+4 > len(wire) {
			return nil, errors.New("invalid DNS question")
		}
		offset = next + 4
	}
	for range records {
		_, next, err := dns.UnpackRR(wire, offset)
		if err != nil || next <= offset {
			return nil, errors.New("invalid DNS resource record")
		}
		offset = next
	}
	if offset != len(wire) {
		return nil, errors.New("trailing DNS bytes")
	}
	message := new(dns.Msg)
	if err := message.Unpack(wire); err != nil {
		return nil, err
	}
	return message, nil
}
