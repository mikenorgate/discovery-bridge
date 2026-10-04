package observation

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMonitorScopesNotificationsAndRejectsLoss(t *testing.T) {
	for _, test := range []struct {
		name    string
		kind    uint16
		index   uint32
		size    int
		changed bool
		invalid bool
	}{
		{"other link", unix.RTM_NEWLINK, 3, unix.SizeofIfInfomsg, false, false},
		{"other address", unix.RTM_NEWADDR, 3, unix.SizeofIfAddrmsg, false, false},
		{"LAN link removed", unix.RTM_DELLINK, 2, unix.SizeofIfInfomsg, true, false},
		{"LAN address removed", unix.RTM_DELADDR, 2, unix.SizeofIfAddrmsg, true, false},
		{"event loss", unix.NLMSG_OVERRUN, 0, 0, false, true},
		{"short address", unix.RTM_NEWADDR, 2, 4, false, true},
		{"missing index", unix.RTM_NEWLINK, 0, unix.SizeofIfInfomsg, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, unix.NLMSG_HDRLEN+test.size)
			binary.NativeEndian.PutUint32(data[:4], uint32(len(data)))
			binary.NativeEndian.PutUint16(data[4:6], test.kind)
			if test.size >= 8 {
				binary.NativeEndian.PutUint32(data[unix.NLMSG_HDRLEN+4:], test.index)
			}
			changed, err := monitoredChange(data, []int{2})
			if changed != test.changed || (err != nil) != test.invalid {
				t.Fatalf("changed=%v error=%v", changed, err)
			}
		})
	}
}
