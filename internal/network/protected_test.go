package network

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

const arpTable = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.30     0x1         0x2         00:00:00:00:00:00     *        eth0
`

func TestArpLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", "aa:bb:cc:dd:ee:01"},
		{"192.168.1.20", ""}, // incomplete entry (flags 0x0)
		{"192.168.1.30", ""}, // zero MAC
		{"10.0.0.1", ""},     // absent
	}
	for _, tc := range tests {
		got := arpLookup(strings.NewReader(arpTable), netip.MustParseAddr(tc.ip))
		if (got == nil && tc.want != "") || (got != nil && got.String() != tc.want) {
			t.Errorf("%s: got %v, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestProtectedTargets_IncludesGatewayAndSkipsLoopback(t *testing.T) {
	t.Parallel()
	topo := &NetworkTopology{DefaultGateway: net.ParseIP("192.0.2.254")}
	addrs, _ := ProtectedTargets(topo)
	foundGW := false
	for _, a := range addrs {
		if a.IsLoopback() {
			t.Errorf("loopback %s must not be protected (it never reaches the hook)", a)
		}
		if a == netip.MustParseAddr("192.0.2.254") {
			foundGW = true
		}
	}
	if !foundGW {
		t.Fatalf("gateway missing from %v", addrs)
	}
	if a, m := ProtectedTargets(nil); m != nil && len(a) == 0 {
		t.Fatal("nil topology must not panic")
	}
}
