package network

import (
	"strings"
	"testing"
)

const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
tun0	00000000	0100080A	0003	0	0	50	00000000	0	0	0
wlp4s0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
wlp4s0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
broken	zz	zz	zz
`

func TestParseRoutes(t *testing.T) {
	t.Parallel()
	rs := parseRoutes(strings.NewReader(procRoute))
	if len(rs) != 4 {
		t.Fatalf("routes: %+v", rs)
	}
	if gw := routeGateway(rs, "wlp4s0"); gw.String() != "192.168.1.1" {
		t.Fatalf("wlp4s0 gateway: %v", gw)
	}
	if gw := routeGateway(rs, "tun0"); gw.String() != "10.8.0.1" {
		t.Fatalf("tun0 gateway: %v", gw)
	}
	if gw := routeGateway(rs, "docker0"); gw != nil {
		t.Fatalf("docker0 has no gateway, got %v", gw)
	}
	cases := map[string]int{"tun0": 50, "wlp4s0": 600, "docker0": 0, "eth9": 0}
	for iface, want := range cases {
		if got := routeMetric(rs, iface); got != want {
			t.Errorf("%s metric: got %d, want %d", iface, got, want)
		}
	}
}
