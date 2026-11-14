package network

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// ProtectedTargets returns the addresses a policy rule must not cover by
// accident: this host's own IPs, the default gateway, and the gateway's MAC
// when it is in the ARP table. Blocking any of them would cut the console
// (and usually the whole host) off the network.
func ProtectedTargets(topology *NetworkTopology) ([]netip.Addr, []net.HardwareAddr) {
	var addrs []netip.Addr
	if ifAddrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifAddrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && !ip.Unmap().IsLoopback() {
					addrs = append(addrs, ip.Unmap())
				}
			}
		}
	}
	var macs []net.HardwareAddr
	if topology != nil && topology.DefaultGateway != nil {
		if gw, ok := netip.AddrFromSlice(topology.DefaultGateway); ok {
			gw = gw.Unmap()
			addrs = append(addrs, gw)
			if f, err := os.Open("/proc/net/arp"); err == nil {
				if mac := arpLookup(f, gw); mac != nil {
					macs = append(macs, mac)
				}
				_ = f.Close()
			}
		}
	}
	return addrs, macs
}

// arpLookup finds ip in /proc/net/arp content:
//
//	IP address  HW type  Flags  HW address         Mask  Device
//	192.168.1.1 0x1      0x2    aa:bb:cc:dd:ee:ff  *     eth0
func arpLookup(r io.Reader, ip netip.Addr) net.HardwareAddr {
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] != ip.String() || f[2] == "0x0" {
			continue
		}
		if mac, err := net.ParseMAC(f[3]); err == nil && len(mac) == 6 && !isZeroMAC(mac) {
			return mac
		}
	}
	return nil
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}
