package monitor

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/databases"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/network"
	"github.com/zrougamed/cerberus/internal/utils"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/tidwall/buntdb"
)

type NetworkMonitor struct {
	Cache          *lru.Cache[string, *models.DeviceInfo]
	db             *buntdb.DB
	ouiDB          map[string]string
	serviceDB      map[uint16]*models.ServiceInfo
	mu             sync.RWMutex
	newDeviceChan  chan *models.DeviceInfo
	newPatternChan chan *models.CommunicationPattern
	localSubnet    *net.IPNet
	Stats          struct {
		TotalPackets uint64
		ArpPackets   uint64
		TcpPackets   uint64
		UdpPackets   uint64
		IcmpPackets  uint64
		DnsPackets   uint64
		HttpPackets  uint64
		TlsPackets   uint64
	}
}

func NewNetworkMonitor(cacheSize int, dbPath string) (*NetworkMonitor, error) {
	cache, err := lru.New[string, *models.DeviceInfo](cacheSize)
	if err != nil {
		return nil, err
	}

	db, err := buntdb.Open(dbPath)
	if err != nil {
		return nil, err
	}

	db.CreateIndex("mac", "*", buntdb.IndexJSON("mac"))
	db.CreateIndex("last_seen", "*", buntdb.IndexJSON("last_seen"))

	localSubnet := network.DetectLocalSubnet()

	nm := &NetworkMonitor{
		Cache:          cache,
		db:             db,
		ouiDB:          databases.LoadOUIDatabase(),
		serviceDB:      databases.LoadServiceDatabase(),
		newDeviceChan:  make(chan *models.DeviceInfo, 100),
		newPatternChan: make(chan *models.CommunicationPattern, 1000),
		localSubnet:    localSubnet,
	}

	go nm.persistWorker()
	go nm.newDeviceNotifier()
	go nm.newPatternNotifier()

	return nm, nil
}

func (nm *NetworkMonitor) Close() error {
	close(nm.newDeviceChan)
	close(nm.newPatternChan)
	return nm.db.Close()
}

func (nm *NetworkMonitor) classifyTCPTraffic(srcIP, dstIP string, srcPort, dstPort uint16, tcpFlags uint8) models.TrafficType {
	// Check well-known services by port
	// TODO: Expand this list to include more services
	switch dstPort {
	case 80:
		return models.TrafficTCPHTTP
	case 443:
		return models.TrafficTCPHTTPS
	case 22:
		return models.TrafficTCPSSH
	}

	// Check TCP flags
	if tcpFlags&0x02 != 0 && tcpFlags&0x10 == 0 {
		return models.TrafficTCPSYN
	} else if tcpFlags&0x02 != 0 && tcpFlags&0x10 != 0 {
		return models.TrafficTCPSYNACK
	} else if tcpFlags&0x01 != 0 {
		return models.TrafficTCPFIN
	} else if tcpFlags&0x04 != 0 {
		return models.TrafficTCPRST
	} else if tcpFlags&0x10 != 0 {
		return models.TrafficTCPACK
	}

	return models.TrafficTCPCustom
}

func (nm *NetworkMonitor) classifyUDPTraffic(srcIP, dstIP string, srcPort, dstPort uint16) models.TrafficType {
	if dstPort == 53 || srcPort == 53 {
		return models.TrafficUDPDNS
	} else if dstPort == 67 || dstPort == 68 {
		return models.TrafficUDPDHCP
	} else if dstPort == 123 {
		return models.TrafficUDPNTP
	} else if dstPort == 161 || dstPort == 162 {
		return models.TrafficUDPSNMP
	}
	return models.TrafficUDPCustom
}

func (nm *NetworkMonitor) classifyARPTraffic(srcIP, dstIP string, op uint16) models.TrafficType {
	if srcIP == "0.0.0.0" {
		return models.TrafficARPProbe
	}
	if srcIP == dstIP {
		return models.TrafficARPAnnounce
	}
	if op == 1 {
		return models.TrafficARPRequest
	} else if op == 2 {
		return models.TrafficARPReply
	}
	return models.TrafficARPRequest
}

func (nm *NetworkMonitor) classifyICMPTraffic(icmpType, icmpCode uint8) models.TrafficType {
	switch icmpType {
	case 0:
		return models.TrafficICMPEchoReply
	case 3:
		return models.TrafficICMPDestUnreach
	case 5:
		return models.TrafficICMPRedirect
	case 8:
		return models.TrafficICMPEchoRequest
	case 11:
		return models.TrafficICMPTimeExceeded
	default:
		return models.TrafficICMPCustom
	}
}

func (nm *NetworkMonitor) classifyDNSTraffic(payload [32]byte) models.TrafficType {
	// DNS queries have QR bit = 0, responses have QR bit = 1
	// Flags are in bytes 2-3, QR is the first bit of byte 2
	if len(payload) >= 3 {
		flags := uint16(payload[2])<<8 | uint16(payload[3])
		if flags&0x8000 != 0 {
			return models.TrafficDNSResponse
		}
	}
	return models.TrafficDNSQuery
}

func (nm *NetworkMonitor) classifyHTTPTraffic(payload [32]byte) models.TrafficType {
	str := string(payload[:])
	if strings.HasPrefix(str, "GET ") {
		return models.TrafficHTTPGET
	} else if strings.HasPrefix(str, "POST ") {
		return models.TrafficHTTPPOST
	}
	return models.TrafficHTTPRequest
}

func (nm *NetworkMonitor) classifyTLSTraffic(payload [32]byte) models.TrafficType {
	// TLS handshake record type 0x16, followed by version
	if len(payload) >= 6 {
		// Check for Client Hello (handshake type 0x01)
		if payload[0] == 0x16 && payload[5] == 0x01 {
			return models.TrafficTLSClientHello
		}
		// Check for Server Hello (handshake type 0x02)
		if payload[0] == 0x16 && payload[5] == 0x02 {
			return models.TrafficTLSServerHello
		}
	}
	return models.TrafficTLSHandshake
}

func (nm *NetworkMonitor) getServiceName(port uint16, protocol string) string {
	if svc, ok := nm.serviceDB[port]; ok && (svc.Protocol == protocol || svc.Protocol == "BOTH") {
		return svc.Service
	}
	return fmt.Sprintf("%s/%d", protocol, port)
}

func (nm *NetworkMonitor) TrackEvent(evt *models.NetworkEvent) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.Stats.TotalPackets++

	srcMAC := utils.MacToString(evt.SrcMac)
	srcIP := utils.IntToIP(evt.SrcIP).String()
	dstIP := utils.IntToIP(evt.DstIP).String()

	var trafficType models.TrafficType
	var service string
	var protocol string
	var l7Info string

	switch evt.EventType {
	case models.EVENT_TYPE_ARP:
		nm.Stats.ArpPackets++
		trafficType = nm.classifyARPTraffic(srcIP, dstIP, evt.ArpOp)
		protocol = "ARP"
		service = string(trafficType)

	case models.EVENT_TYPE_TCP:
		nm.Stats.TcpPackets++
		trafficType = nm.classifyTCPTraffic(srcIP, dstIP, evt.SrcPort, evt.DstPort, evt.TCPFlags)
		protocol = "TCP"
		service = nm.getServiceName(evt.DstPort, "TCP")
		l7Info = utils.GetL7Info(evt)

	case models.EVENT_TYPE_UDP:
		nm.Stats.UdpPackets++
		trafficType = nm.classifyUDPTraffic(srcIP, dstIP, evt.SrcPort, evt.DstPort)
		protocol = "UDP"
		service = nm.getServiceName(evt.DstPort, "UDP")
		l7Info = utils.GetL7Info(evt)

	case models.EVENT_TYPE_ICMP:
		nm.Stats.IcmpPackets++
		trafficType = nm.classifyICMPTraffic(evt.ICMPType, evt.ICMPCode)
		protocol = "ICMP"
		service = string(trafficType)

	case models.EVENT_TYPE_DNS:
		nm.Stats.DnsPackets++
		trafficType = nm.classifyDNSTraffic(evt.L7Payload)
		protocol = "DNS"
		service = "DNS"
		l7Info = utils.GetL7Info(evt)

	case models.EVENT_TYPE_HTTP:
		nm.Stats.HttpPackets++
		trafficType = nm.classifyHTTPTraffic(evt.L7Payload)
		protocol = "HTTP"
		service = "HTTP"
		l7Info = utils.GetL7Info(evt)

	case models.EVENT_TYPE_TLS:
		nm.Stats.TlsPackets++
		trafficType = nm.classifyTLSTraffic(evt.L7Payload)
		protocol = "TLS"
		service = "TLS"
		l7Info = utils.GetL7Info(evt)
	}

	// Get or create device
	device, found := nm.Cache.Get(srcMAC)
	isNew := !found

	if !found {
		var dbDevice *models.DeviceInfo
		nm.db.View(func(tx *buntdb.Tx) error {
			val, err := tx.Get(srcMAC)
			if err == nil {
				json.Unmarshal([]byte(val), &dbDevice)
				device = dbDevice
				isNew = false
			}
			return nil
		})
	}

	if device == nil {
		vendor := nm.lookupVendor(srcMAC)
		device = &models.DeviceInfo{
			MAC:               srcMAC,
			IP:                srcIP,
			Vendor:            vendor,
			Interface:         utils.IfIndexToName(evt.IfIndex),
			FirstSeen:         time.Now(),
			LastSeen:          time.Now(),
			Targets:           []string{},
			Services:          make(map[string]int),
			DNSDomains:        make(map[string]int),
			HTTPHosts:         make(map[string]int),
			TLSSNIs:           make(map[string]int),
			SeenPatterns:      make(map[string]bool),
			TrafficTypeCounts: make(map[models.TrafficType]int),
			FlowStats:         make(map[string]*models.FlowStats),
		}
		isNew = true
	}

	// Initialize maps if nil
	if device.SeenPatterns == nil {
		device.SeenPatterns = make(map[string]bool)
	}
	if device.TrafficTypeCounts == nil {
		device.TrafficTypeCounts = make(map[models.TrafficType]int)
	}
	if device.Services == nil {
		device.Services = make(map[string]int)
	}
	if device.FlowStats == nil {
		device.FlowStats = make(map[string]*models.FlowStats)
	}
	if device.DNSDomains == nil {
		device.DNSDomains = make(map[string]int)
	}
	if device.HTTPHosts == nil {
		device.HTTPHosts = make(map[string]int)
	}
	if device.TLSSNIs == nil {
		device.TLSSNIs = make(map[string]int)
	}

	// Update device info
	device.LastSeen = time.Now()
	if device.IP != srcIP && srcIP != "0.0.0.0" {
		device.IP = srcIP
	}

	device.TrafficTypeCounts[trafficType]++
	device.Services[service]++

	// Track L7 information
	if l7Info != "" {
		switch evt.EventType {
		case models.EVENT_TYPE_DNS:
			device.DNSDomains[l7Info]++
			device.DNSQueries++
		case models.EVENT_TYPE_HTTP:
			device.HTTPHosts[l7Info]++
			device.HTTPRequests++
		case models.EVENT_TYPE_TLS:
			device.TLSSNIs[l7Info]++
			device.TLSConnections++
		}
	}

	// Track connections
	switch evt.EventType {
	case models.EVENT_TYPE_TCP, models.EVENT_TYPE_HTTP, models.EVENT_TYPE_TLS:
		device.TCPConnections++
	case models.EVENT_TYPE_UDP, models.EVENT_TYPE_DNS:
		device.UDPConnections++
	case models.EVENT_TYPE_ICMP:
		device.ICMPPackets++
	case models.EVENT_TYPE_ARP:
		if evt.ArpOp == 1 {
			device.RequestCount++
		} else {
			device.ReplyCount++
		}
	}

	// Track targets
	if dstIP != "0.0.0.0" && !utils.Contains(device.Targets, dstIP) {
		device.Targets = append(device.Targets, dstIP)
		if len(device.Targets) > 20 {
			device.Targets = device.Targets[1:]
		}
	}

	// Check for new communication pattern
	patternKey := fmt.Sprintf("%s:%s->%s:%d:%s", protocol, srcIP, dstIP, evt.DstPort, trafficType)
	if !device.SeenPatterns[patternKey] {
		device.SeenPatterns[patternKey] = true

		// Get interface name from index
		ifName := utils.IfIndexToName(evt.IfIndex)

		pattern := &models.CommunicationPattern{
			SrcMAC:      srcMAC,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			DstPort:     evt.DstPort,
			Protocol:    protocol,
			TrafficType: trafficType,
			Service:     service,
			Timestamp:   time.Now(),
			L7Info:      l7Info,
			Interface:   ifName,
		}

		select {
		case nm.newPatternChan <- pattern:
		default:
		}
	}

	// Update cache
	nm.Cache.Add(srcMAC, device)

	// Notify if new device
	// TODO: add to syslog or alerting system
	if isNew {
		select {
		case nm.newDeviceChan <- device:
		default:
		}
	}
}

func (nm *NetworkMonitor) persistWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.RLock()
		keys := nm.Cache.Keys()
		nm.mu.RUnlock()

		nm.db.Update(func(tx *buntdb.Tx) error {
			for _, mac := range keys {
				if device, ok := nm.Cache.Get(mac); ok {
					data, _ := json.Marshal(device)
					tx.Set(mac, string(data), nil)
				}
			}
			return nil
		})
	}
}

func (nm *NetworkMonitor) newDeviceNotifier() {
	for device := range nm.newDeviceChan {
		fmt.Printf("\nNEW DEVICE DETECTED!\n")
		fmt.Printf("   MAC:     %s\n", device.MAC)
		fmt.Printf("   IP:      %s\n", device.IP)
		fmt.Printf("   Vendor:  %s\n", device.Vendor)
		fmt.Printf("   First Seen: %s\n\n", device.FirstSeen.Format("2006-01-02 15:04:05"))
	}
}

func (nm *NetworkMonitor) newPatternNotifier() {
	for pattern := range nm.newPatternChan {
		device, _ := nm.Cache.Get(pattern.SrcMAC)

		vendor := "Unknown"
		if device != nil {
			vendor = device.Vendor
		}

		l7Suffix := ""
		if pattern.L7Info != "" {
			l7Suffix = fmt.Sprintf(" [%s]", pattern.L7Info)
		}

		// Add interface name to output
		ifPrefix := ""
		if pattern.Interface != "" {
			ifPrefix = fmt.Sprintf("[%s] ", pattern.Interface)
		}

		if pattern.DstPort > 0 {
			fmt.Printf("%s[%s] %s (%s) [%s] → %s:%d (%s)%s\n",
				ifPrefix,
				pattern.Protocol,
				pattern.SrcIP,
				pattern.SrcMAC,
				vendor,
				pattern.DstIP,
				pattern.DstPort,
				pattern.Service,
				l7Suffix,
			)
		} else {
			fmt.Printf("%s[%s] %s (%s) [%s] → %s (%s)%s\n",
				ifPrefix,
				pattern.Protocol,
				pattern.SrcIP,
				pattern.SrcMAC,
				vendor,
				pattern.DstIP,
				pattern.Service,
				l7Suffix,
			)
		}
	}
}

func (nm *NetworkMonitor) lookupVendor(mac string) string {
	parts := strings.Split(strings.ToUpper(mac), ":")
	if len(parts) < 3 {
		return "Unknown"
	}
	oui := strings.Join(parts[:3], ":")

	if vendor, ok := nm.ouiDB[oui]; ok {
		return vendor
	}
	return "Unknown"
}

func (nm *NetworkMonitor) GetStats() map[string]*models.DeviceInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	stats := make(map[string]*models.DeviceInfo)
	for _, mac := range nm.Cache.Keys() {
		if device, ok := nm.Cache.Get(mac); ok {
			stats[mac] = device
		}
	}
	return stats
}

func (nm *NetworkMonitor) PrintStats() {
	stats := nm.GetStats()

	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║              NETWORK STATISTICS SUMMARY                       ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Total Devices: %-47d ║\n", len(stats))
	fmt.Printf("║ Total Packets: %-47d ║\n", nm.Stats.TotalPackets)
	fmt.Printf("║   - ARP:  %-52d ║\n", nm.Stats.ArpPackets)
	fmt.Printf("║   - TCP:  %-52d ║\n", nm.Stats.TcpPackets)
	fmt.Printf("║   - UDP:  %-52d ║\n", nm.Stats.UdpPackets)
	fmt.Printf("║   - ICMP: %-52d ║\n", nm.Stats.IcmpPackets)
	fmt.Printf("║   - DNS:  %-52d ║\n", nm.Stats.DnsPackets)
	fmt.Printf("║   - HTTP: %-52d ║\n", nm.Stats.HttpPackets)
	fmt.Printf("║   - TLS:  %-52d ║\n", nm.Stats.TlsPackets)
	fmt.Printf("╚═══════════════════════════════════════════════════════════════╝\n\n")

	for mac, device := range stats {
		fmt.Printf("┌─ Device: %s\n", mac)
		fmt.Printf("│  IP: %s | Vendor: %s\n", device.IP, device.Vendor)
		fmt.Printf("│  ARP: Req=%d Reply=%d | TCP: %d | UDP: %d | ICMP: %d\n",
			device.RequestCount, device.ReplyCount, device.TCPConnections,
			device.UDPConnections, device.ICMPPackets)

		if device.DNSQueries > 0 {
			fmt.Printf("│  DNS Queries: %d", device.DNSQueries)
			if len(device.DNSDomains) > 0 {
				fmt.Printf(" | Top Domains: ")
				count := 0
				for domain, cnt := range device.DNSDomains {
					if count >= 3 {
						break
					}
					fmt.Printf("%s(%d) ", domain, cnt)
					count++
				}
			}
			fmt.Println()
		}

		if device.HTTPRequests > 0 {
			fmt.Printf("│  HTTP Requests: %d\n", device.HTTPRequests)
		}

		if device.TLSConnections > 0 {
			fmt.Printf("│  TLS Connections: %d\n", device.TLSConnections)
		}

		if len(device.Services) > 0 {
			fmt.Printf("│  Top Services: ")
			count := 0
			for svc, cnt := range device.Services {
				if count >= 5 {
					break
				}
				fmt.Printf("%s(%d) ", svc, cnt)
				count++
			}
			fmt.Println()
		}

		fmt.Printf("│  First: %s | Last: %s\n",
			device.FirstSeen.Format("15:04:05"),
			device.LastSeen.Format("15:04:05"))

		if len(device.Targets) > 0 {
			fmt.Printf("│  Recent Targets: %v\n", device.Targets[max(0, len(device.Targets)-3):])
		}
		fmt.Println("└─")
	}
}
