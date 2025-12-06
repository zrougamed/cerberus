package network

import "net"

func DetectLocalSubnet() *net.IPNet {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					return ipnet
				}
			}
		}
	}
	// TODO: Improve subnet detection
	// Fallback to common private subnet
	_, subnet, _ := net.ParseCIDR("192.168.0.0/16")
	return subnet
}
