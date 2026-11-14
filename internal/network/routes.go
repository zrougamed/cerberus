package network

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// route is one IPv4 entry of the main routing table.
type route struct {
	iface   string
	gateway net.IP // nil when the route has no gateway
	metric  int
}

const rtfGateway = 0x2 // RTF_GATEWAY

// readRoutes parses /proc/net/route (the same main table `ip route show`
// prints for IPv4), so no external command is run.
func readRoutes() ([]route, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseRoutes(f), nil
}

// parseRoutes reads the /proc/net/route format:
//
//	Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//	eth0  00000000    0101A8C0 0003 0      0   600    00000000 ...
//
// Addresses are little-endian hex.
func parseRoutes(r io.Reader) []route {
	var out []route
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 7 {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		metric, err2 := strconv.Atoi(f[6])
		if err1 != nil || err2 != nil {
			continue
		}
		rt := route{iface: f[0], metric: metric}
		if flags&rtfGateway != 0 {
			if gw := hexIPv4(f[2]); gw != nil && !gw.IsUnspecified() {
				rt.gateway = gw
			}
		}
		out = append(out, rt)
	}
	return out
}

func hexIPv4(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return nil
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, binary.BigEndian.Uint32(b))
	return ip
}

// routeMetric is the metric of the interface's first route, 0 when it has
// none (the old `ip route show dev X` parsing returned the same).
func routeMetric(routes []route, iface string) int {
	for _, r := range routes {
		if r.iface == iface {
			return r.metric
		}
	}
	return 0
}

// routeGateway is the first gateway reachable through the interface.
func routeGateway(routes []route, iface string) net.IP {
	for _, r := range routes {
		if r.iface == iface && r.gateway != nil {
			return r.gateway
		}
	}
	return nil
}
