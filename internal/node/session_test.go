package node

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func claimPacket(t *testing.T, reply bool, rr string) []byte {
	t.Helper()
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: reply}}
	value, err := dns.NewRR(rr)
	if err != nil {
		t.Fatal(err)
	}
	if reply {
		message.Answer = []dns.RR{value}
	} else {
		message.Ns = []dns.RR{value}
	}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPassiveClaimsKeepLocalOwnershipUntilExpiry(t *testing.T) {
	claims := make(map[string]time.Duration)
	for _, reply := range []bool{true, false} {
		consumed, err := observeClaims(claimPacket(t, reply, "Sensor.local. 20 IN AAAA 2001:db8:2::42"), time.Second, claims)
		if err != nil || !consumed || claims["sensor.local."] != 21*time.Second {
			t.Fatal(consumed, claims, err)
		}
	}
	if _, err := observeClaims(claimPacket(t, true, "sensor.local. 0 IN AAAA 2001:db8:2::42"), 2*time.Second, claims); err != nil || claims["sensor.local."] != 21*time.Second {
		t.Fatal("goodbye shortened independent ownership evidence", claims, err)
	}
	if _, err := observeClaims(claimPacket(t, true, "_http._tcp.local. 10 IN PTR Sensor._http._tcp.local."), 22*time.Second, claims); err != nil || len(claims) != 0 {
		t.Fatal("expired claim or shared PTR was retained", claims, err)
	}
}

func TestPassiveClaimFailuresDistinguishMalformedPacketsFromCapacity(t *testing.T) {
	claims := make(map[string]time.Duration)
	if _, err := observeClaims([]byte{0}, time.Second, claims); err == nil || errors.Is(err, errClaimCapacity) {
		t.Fatal(err)
	}
	for index := range 256 {
		claims[fmt.Sprintf("client%d.local.", index)] = 20 * time.Second
	}
	if _, err := observeClaims(claimPacket(t, true, "other.local. 10 IN A 192.0.2.42"), time.Second, claims); !errors.Is(err, errClaimCapacity) || len(claims) != 256 {
		t.Fatal("claim capacity did not fail closed", len(claims), err)
	}
}
