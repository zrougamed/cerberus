package network

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// NetworkInfo represents detailed network interface information
type NetworkInfo struct {
	InterfaceName string
	IPAddress     net.IP
	Subnet        *net.IPNet
	Gateway       net.IP
	IsPrivate     bool
	IsDockerNet   bool
	IsVirtualNet  bool
	Metric        int // Route metric/priority
}

// NetworkTopology contains complete network topology information
type NetworkTopology struct {
	LocalSubnets    []*net.IPNet
	PrimarySubnet   *net.IPNet
	DefaultGateway  net.IP
	Interfaces      map[string]*NetworkInfo
	PrivateRanges   []*net.IPNet
	DockerNetworks  []*net.IPNet
	VirtualNetworks []*net.IPNet
}

var (
	// RFC 1918 Private Address Ranges
	privateRanges = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	// Common virtual/container network prefixes
	virtualPrefixes = []string{
		"docker", "br-", "veth", "cali", "flannel", "weave",
		"kube", "cni", "lxc", "vmnet", "vbox",
	}

	// Docker default networks
	dockerNetworks = []string{
		"172.17.0.0/16", // Docker default bridge
		"172.18.0.0/16", // Docker custom networks often start here
	}
)

// DetectNetworkTopology performs comprehensive network topology detection
func DetectNetworkTopology() (*NetworkTopology, error) {
	topo := &NetworkTopology{
		LocalSubnets:    make([]*net.IPNet, 0),
		Interfaces:      make(map[string]*NetworkInfo),
		PrivateRanges:   parseRanges(privateRanges),
		DockerNetworks:  parseRanges(dockerNetworks),
		VirtualNetworks: make([]*net.IPNet, 0),
	}

	// Detect default gateway
	topo.DefaultGateway = detectDefaultGateway()

	// Enumerate all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	var primaryInterface *NetworkInfo
	highestPriority := 9999

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue // Skip non-IPv4
			}

			netInfo := &NetworkInfo{
				InterfaceName: iface.Name,
				IPAddress:     ipnet.IP,
				Subnet:        ipnet,
				IsPrivate:     isPrivateIP(ipnet.IP, topo.PrivateRanges),
				IsDockerNet:   isDockerNetwork(iface.Name, ipnet),
				IsVirtualNet:  isVirtualInterface(iface.Name),
				Metric:        getInterfaceMetric(iface.Name),
			}

			// Try to find gateway for this interface
			netInfo.Gateway = findGatewayForInterface(iface.Name, ipnet, topo.DefaultGateway)

			topo.Interfaces[iface.Name] = netInfo
			topo.LocalSubnets = append(topo.LocalSubnets, ipnet)

			// Classify virtual networks
			if netInfo.IsVirtualNet || netInfo.IsDockerNet {
				topo.VirtualNetworks = append(topo.VirtualNetworks, ipnet)
			}

			// Determine primary interface (lowest metric, has gateway, is private)
			if netInfo.IsPrivate && !netInfo.IsVirtualNet && netInfo.Gateway != nil {
				if netInfo.Metric < highestPriority {
					highestPriority = netInfo.Metric
					primaryInterface = netInfo
				}
			}
		}
	}

	// Set primary subnet
	if primaryInterface != nil {
		topo.PrimarySubnet = primaryInterface.Subnet
	} else if len(topo.LocalSubnets) > 0 {
		// Fallback: first non-virtual subnet
		for _, subnet := range topo.LocalSubnets {
			if !isVirtualSubnet(subnet, topo.VirtualNetworks) {
				topo.PrimarySubnet = subnet
				break
			}
		}
	}

	// Ultimate fallback
	if topo.PrimarySubnet == nil {
		_, fallback, _ := net.ParseCIDR("192.168.1.0/24")
		topo.PrimarySubnet = fallback
	}

	return topo, nil
}

// DetectLocalSubnet returns the primary local subnet (backward compatible)
func DetectLocalSubnet() *net.IPNet {
	topo, err := DetectNetworkTopology()
	if err != nil || topo.PrimarySubnet == nil {
		_, fallback, _ := net.ParseCIDR("192.168.1.0/24")
		return fallback
	}
	return topo.PrimarySubnet
}

// detectDefaultGateway detects the system's default gateway
func detectDefaultGateway() net.IP {
	switch runtime.GOOS {
	case "linux":
		return detectGatewayLinux()
	case "darwin":
		return detectGatewayDarwin()
	case "windows":
		return detectGatewayWindows()
	default:
		return nil
	}
}

// detectGatewayLinux detects gateway on Linux systems
func detectGatewayLinux() net.IP {
	// Try reading /proc/net/route
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err == nil {
		// Parse: default via 192.168.1.1 dev eth0
		re := regexp.MustCompile(`default via ([0-9.]+)`)
		matches := re.FindStringSubmatch(string(output))
		if len(matches) > 1 {
			return net.ParseIP(matches[1])
		}
	}

	// Fallback: try route command
	output, err = exec.Command("route", "-n").Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					return net.ParseIP(fields[1])
				}
			}
		}
	}

	return nil
}

// detectGatewayDarwin detects gateway on macOS
func detectGatewayDarwin() net.IP {
	output, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil
	}

	// Parse: gateway: 192.168.1.1
	re := regexp.MustCompile(`gateway:\s+([0-9.]+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return net.ParseIP(matches[1])
	}

	return nil
}

// detectGatewayWindows detects gateway on Windows
func detectGatewayWindows() net.IP {
	output, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return nil
	}

	// Parse Windows route output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) > 2 {
				return net.ParseIP(fields[2])
			}
		}
	}

	return nil
}

// getInterfaceMetric gets the routing metric for an interface
func getInterfaceMetric(ifaceName string) int {
	switch runtime.GOOS {
	case "linux":
		output, err := exec.Command("ip", "route", "show", "dev", ifaceName).Output()
		if err != nil {
			return 100
		}

		// Parse: metric value
		re := regexp.MustCompile(`metric (\d+)`)
		matches := re.FindStringSubmatch(string(output))
		if len(matches) > 1 {
			metric := 0
			fmt.Sscanf(matches[1], "%d", &metric)
			return metric
		}
		return 0 // Linux default is 0 if not specified

	case "darwin":
		// macOS doesn't easily expose metrics, use heuristics
		if strings.HasPrefix(ifaceName, "en") {
			return 0 // Ethernet/WiFi gets priority
		}
		return 100

	case "windows":
		// Windows metric detection would go here
		return 100

	default:
		return 100
	}
}

// findGatewayForInterface finds the gateway for a specific interface
func findGatewayForInterface(ifaceName string, subnet *net.IPNet, defaultGW net.IP) net.IP {
	// If default gateway is in this subnet, use it
	if defaultGW != nil && subnet.Contains(defaultGW) {
		return defaultGW
	}

	switch runtime.GOOS {
	case "linux":
		output, err := exec.Command("ip", "route", "show", "dev", ifaceName).Output()
		if err != nil {
			return nil
		}

		// Look for default or gateway
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "default") || strings.Contains(line, "via") {
				re := regexp.MustCompile(`via ([0-9.]+)`)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					return net.ParseIP(matches[1])
				}
			}
		}

	case "darwin":
		// Similar for macOS
		return defaultGW
	}

	return nil
}

// isPrivateIP checks if an IP is in private ranges
func isPrivateIP(ip net.IP, privateRanges []*net.IPNet) bool {
	for _, ipnet := range privateRanges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// isDockerNetwork checks if this is a Docker network
func isDockerNetwork(ifaceName string, ipnet *net.IPNet) bool {
	// Check interface name
	if strings.HasPrefix(ifaceName, "docker") || strings.HasPrefix(ifaceName, "br-") {
		return true
	}

	// Check if IP is in Docker ranges
	for _, dockerNet := range dockerNetworks {
		_, ipnetDocker, _ := net.ParseCIDR(dockerNet)
		if ipnetDocker != nil && ipnetDocker.Contains(ipnet.IP) {
			return true
		}
	}

	return false
}

// isVirtualInterface checks if interface name suggests virtual/container network
func isVirtualInterface(ifaceName string) bool {
	lowerName := strings.ToLower(ifaceName)
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	return false
}

// isVirtualSubnet checks if subnet is in virtual networks
func isVirtualSubnet(subnet *net.IPNet, virtualNets []*net.IPNet) bool {
	for _, vnet := range virtualNets {
		if vnet.String() == subnet.String() {
			return true
		}
	}
	return false
}

// parseRanges converts CIDR strings to IPNet slices
func parseRanges(ranges []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, ipnet, err := net.ParseCIDR(r)
		if err == nil {
			result = append(result, ipnet)
		}
	}
	return result
}

// IsLocalIP checks if an IP is in local subnets
func (topo *NetworkTopology) IsLocalIP(ip net.IP) bool {
	for _, subnet := range topo.LocalSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateIP checks if an IP is in private ranges
func (topo *NetworkTopology) IsPrivateIP(ip net.IP) bool {
	for _, ipnet := range topo.PrivateRanges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsDockerIP checks if an IP is in Docker networks
func (topo *NetworkTopology) IsDockerIP(ip net.IP) bool {
	for _, ipnet := range topo.DockerNetworks {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsVirtualIP checks if an IP is in virtual networks
func (topo *NetworkTopology) IsVirtualIP(ip net.IP) bool {
	for _, ipnet := range topo.VirtualNetworks {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// GetInterfaceForIP finds which interface an IP belongs to
func (topo *NetworkTopology) GetInterfaceForIP(ip net.IP) *NetworkInfo {
	for _, netInfo := range topo.Interfaces {
		if netInfo.Subnet.Contains(ip) {
			return netInfo
		}
	}
	return nil
}

// ClassifyIP returns classification of an IP address
func (topo *NetworkTopology) ClassifyIP(ip net.IP) string {
	if ip.IsLoopback() {
		return "LOOPBACK"
	}
	if ip.IsMulticast() {
		return "MULTICAST"
	}
	if ip.IsLinkLocalUnicast() {
		return "LINK_LOCAL"
	}
	if topo.IsDockerIP(ip) {
		return "DOCKER"
	}
	if topo.IsVirtualIP(ip) {
		return "VIRTUAL"
	}
	if topo.IsLocalIP(ip) {
		return "LOCAL"
	}
	if topo.IsPrivateIP(ip) {
		return "PRIVATE"
	}
	return "EXTERNAL"
}

// GetPrimaryInterface returns the primary network interface
func (topo *NetworkTopology) GetPrimaryInterface() *NetworkInfo {
	var primary *NetworkInfo
	lowestMetric := 9999

	for _, netInfo := range topo.Interfaces {
		if netInfo.IsPrivate && !netInfo.IsVirtualNet && netInfo.Gateway != nil {
			if netInfo.Metric < lowestMetric {
				lowestMetric = netInfo.Metric
				primary = netInfo
			}
		}
	}

	return primary
}

// PrintTopology prints network topology information
func (topo *NetworkTopology) PrintTopology() {
	fmt.Println("\n╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║            NETWORK TOPOLOGY DETECTION                    ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")

	if topo.DefaultGateway != nil {
		fmt.Printf("║ Default Gateway:  %-39s║\n", topo.DefaultGateway.String())
	}

	if topo.PrimarySubnet != nil {
		fmt.Printf("║ Primary Subnet:   %-39s║\n", topo.PrimarySubnet.String())
	}

	fmt.Printf("║ Total Interfaces: %-39d║\n", len(topo.Interfaces))
	fmt.Printf("║ Virtual Networks: %-39d║\n", len(topo.VirtualNetworks))
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║ INTERFACES:                                              ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")

	for ifaceName, netInfo := range topo.Interfaces {
		flags := ""
		if netInfo.IsPrivate {
			flags += "P"
		}
		if netInfo.IsVirtualNet {
			flags += "V"
		}
		if netInfo.IsDockerNet {
			flags += "D"
		}

		fmt.Printf("║ %-10s │ %-15s │ %-20s ║\n",
			ifaceName,
			netInfo.IPAddress.String(),
			netInfo.Subnet.String())

		if netInfo.Gateway != nil {
			fmt.Printf("║            │ GW: %-12s │ Metric: %-3d Flags: %-3s║\n",
				netInfo.Gateway.String(),
				netInfo.Metric,
				flags)
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println("Flags: P=Private, V=Virtual, D=Docker")
}
