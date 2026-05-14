package monitor

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/databases"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/network"
	"github.com/zrougamed/cerberus/internal/utils"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/oschwald/geoip2-golang"
	"github.com/tidwall/buntdb"
)

type NetworkMonitor struct {
	Cache          *lru.Cache[string, *models.DeviceInfo]
	db             *buntdb.DB
	ouiDB          *databases.OUIDatabase
	serviceDB      *databases.ServiceDatabase
	mu             sync.RWMutex
	newDeviceChan  chan *models.DeviceInfo
	newPatternChan chan *models.CommunicationPattern
	alerts         []models.AlertEvent
	alertRuleState map[string]bool
	alertConfig    models.AlertRuleConfig
	baselines      *securityBaselines
	anomaly        *anomalyDetector
	geoipDB        *geoip2.Reader
	topology       *network.NetworkTopology
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

var knownDoHEndpoints = map[string]struct{}{
	"1.1.1.1":         {},
	"1.0.0.1":         {},
	"8.8.8.8":         {},
	"8.8.4.4":         {},
	"9.9.9.9":         {},
	"149.112.112.112": {},
	"208.67.222.222":  {},
	"208.67.220.220":  {},
	"94.140.14.14":    {},
	"94.140.15.15":    {},
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

	topology, err := network.DetectNetworkTopology()
	if err != nil {
		topology = nil
	}

	online := databases.OnlineDB()
	oui, _ := databases.NewOUIDatabase(online)
	svc, _ := databases.NewServiceDatabase(online)

	nm := &NetworkMonitor{
		Cache:          cache,
		db:             db,
		ouiDB:          oui,
		serviceDB:      svc,
		newDeviceChan:  make(chan *models.DeviceInfo, 100),
		newPatternChan: make(chan *models.CommunicationPattern, 1000),
		alerts:         make([]models.AlertEvent, 0, 128),
		alertRuleState: make(map[string]bool),
		alertConfig: models.AlertRuleConfig{
			MaxDNSQueriesPerDevice: 200,
			MaxTCPConnections:      500,
			// Targets keeps at most 20 unique dst IPs per device; threshold must be < 20 or target_spread never fires.
			MaxUniqueTargets: 18,
		},
		anomaly:  newAnomalyDetector(),
		topology: topology,
	}
	nm.baselines = newSecurityBaselines(nm.alertConfig)

	go nm.persistWorker()
	go nm.newDeviceNotifier()
	go nm.newPatternNotifier()

	return nm, nil
}

func (nm *NetworkMonitor) Close() error {
	close(nm.newDeviceChan)
	close(nm.newPatternChan)
	if nm.geoipDB != nil {
		_ = nm.geoipDB.Close()
	}
	return nm.db.Close()
}

func (nm *NetworkMonitor) EnableGeoIP(dbPath string) error {
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return err
	}
	nm.mu.Lock()
	if nm.geoipDB != nil {
		_ = nm.geoipDB.Close()
	}
	nm.geoipDB = reader
	nm.mu.Unlock()
	return nil
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

func (nm *NetworkMonitor) classifyDNSTraffic(payload [models.L7PayloadSize]byte) models.TrafficType {
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

func (nm *NetworkMonitor) classifyHTTPTraffic(payload [models.L7PayloadSize]byte) models.TrafficType {
	str := string(payload[:])
	if strings.HasPrefix(str, "GET ") {
		return models.TrafficHTTPGET
	} else if strings.HasPrefix(str, "POST ") {
		return models.TrafficHTTPPOST
	}
	return models.TrafficHTTPRequest
}

func (nm *NetworkMonitor) classifyTLSTraffic(payload [models.L7PayloadSize]byte) models.TrafficType {
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

func (nm *NetworkMonitor) identifyEncryptedDNS(eventType uint8, srcPort, dstPort uint16, srcIP, dstIP string) string {
	if srcPort == 853 || dstPort == 853 {
		return "dot"
	}
	if eventType != models.EVENT_TYPE_TLS && eventType != models.EVENT_TYPE_TCP {
		return ""
	}
	if srcPort != 443 && dstPort != 443 {
		return ""
	}
	if _, ok := knownDoHEndpoints[srcIP]; ok {
		return "doh"
	}
	if _, ok := knownDoHEndpoints[dstIP]; ok {
		return "doh"
	}
	return ""
}

func isGeoIPEligible(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.IsValid() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	return true
}

// updateDeviceIP keeps device.IP pinned to a real LAN address even when a
// gateway forwards packets whose L3 source is some other host. ARP events are
// trusted (the eBPF parser puts the ARP sender protocol address in SrcIP);
// non-ARP IPv4 events only overwrite when srcIP is on a local subnet,
// otherwise the device is flagged as a gateway and the count bumped.
func (nm *NetworkMonitor) updateDeviceIP(device *models.DeviceInfo, evt *models.NetworkEvent, srcIP string) {
	if device == nil || srcIP == "" || srcIP == "0.0.0.0" {
		return
	}

	if evt.EventType == models.EVENT_TYPE_ARP {
		if device.IP != srcIP {
			device.IP = srcIP
		}
		return
	}

	if evt.IsIPv6 == 1 {
		if device.IP == "" {
			device.IP = srcIP
		}
		return
	}

	parsed := net.ParseIP(srcIP)
	if parsed == nil {
		return
	}
	if nm.isLocalIPv4(parsed) {
		if device.IP != srcIP {
			device.IP = srcIP
		}
		return
	}

	device.IsGateway = true
	device.ForwardedSourceCount++
}

// isLocalIPv4 reports whether ip belongs to one of the host's directly
// attached IPv4 subnets. Falls back to net.IP.IsPrivate when topology
// detection failed at startup so the rule still works on minimal hosts.
func (nm *NetworkMonitor) isLocalIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if nm.topology != nil && nm.topology.IsLocalIP(ip) {
		return true
	}
	if nm.topology == nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	return false
}

func (nm *NetworkMonitor) updateGeoForIP(device *models.DeviceInfo, ipStr string) {
	if device == nil || !isGeoIPEligible(ipStr) || nm.geoipDB == nil {
		return
	}
	record, err := nm.geoipDB.City(net.ParseIP(ipStr))
	if err != nil {
		return
	}
	if record.Country.Names != nil {
		device.GeoCountry = record.Country.Names["en"]
	}
	device.GeoCountryCode = record.Country.IsoCode
	if record.City.Names != nil {
		device.GeoCity = record.City.Names["en"]
	}
}

func (nm *NetworkMonitor) getServiceName(port uint16, protocol string) string {
	if nm.serviceDB == nil {
		return fmt.Sprintf("%s/%d", protocol, port)
	}
	return nm.serviceDB.Lookup(port, protocol).Service
}

func (nm *NetworkMonitor) TrackEvent(evt *models.NetworkEvent) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.Stats.TotalPackets++

	srcMAC := utils.MacToString(evt.SrcMac)
	srcIP := utils.EventSrcIPString(evt)
	dstIP := utils.EventDstIPString(evt)

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
			MAC:                srcMAC,
			IP:                 srcIP,
			Vendor:             vendor,
			Interface:          utils.IfIndexToName(evt.IfIndex),
			FirstSeen:          time.Now(),
			LastSeen:           time.Now(),
			Targets:            []string{},
			Services:           make(map[string]int),
			DNSDomains:         make(map[string]int),
			DNSResponseDomains: make(map[string]int),
			DNSQueryTypes:      make(map[string]int),
			DNSResponseCodes:   make(map[string]int),
			EncryptedDNS:       make(map[string]int),
			CorrelatedDomains:  make(map[string]int),
			HTTPHosts:          make(map[string]int),
			TLSSNIs:            make(map[string]int),
			TLSVersions:        make(map[string]int),
			RecentDNSQueries:   make(map[string]time.Time),
			SeenPatterns:       make(map[string]bool),
			TrafficTypeCounts:  make(map[models.TrafficType]int),
			FlowStats:          make(map[string]*models.FlowStats),
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
	if device.DNSResponseDomains == nil {
		device.DNSResponseDomains = make(map[string]int)
	}
	if device.DNSQueryTypes == nil {
		device.DNSQueryTypes = make(map[string]int)
	}
	if device.DNSResponseCodes == nil {
		device.DNSResponseCodes = make(map[string]int)
	}
	if device.EncryptedDNS == nil {
		device.EncryptedDNS = make(map[string]int)
	}
	if device.CorrelatedDomains == nil {
		device.CorrelatedDomains = make(map[string]int)
	}
	if device.TLSSNIs == nil {
		device.TLSSNIs = make(map[string]int)
	}
	if device.TLSVersions == nil {
		device.TLSVersions = make(map[string]int)
	}
	if device.RecentDNSQueries == nil {
		device.RecentDNSQueries = make(map[string]time.Time)
	}

	// Update device info
	device.LastSeen = time.Now()
	nm.updateDeviceIP(device, evt, srcIP)
	nm.updateGeoForIP(device, srcIP)

	device.TrafficTypeCounts[trafficType]++
	device.Services[service]++

	// Track L7 information
	if l7Info != "" {
		switch evt.EventType {
		case models.EVENT_TYPE_DNS:
			device.DNSDomains[l7Info]++
		case models.EVENT_TYPE_HTTP:
			device.HTTPHosts[l7Info]++
			device.HTTPRequests++
		case models.EVENT_TYPE_TLS:
			device.TLSSNIs[l7Info]++
			device.TLSConnections++
			if version := utils.TLSVersionFromPayload(evt.L7Payload); version != "" {
				device.TLSVersions[version]++
			}
		}
	}

	if evt.EventType == models.EVENT_TYPE_DNS {
		device.DNSQueries++
		queryDomain, queryType, responseCode, responseDomain, isResponse := utils.InspectDNSDetails(evt.L7Payload)
		if queryType != "" {
			device.DNSQueryTypes[queryType]++
		}
		if isResponse && responseCode != "" {
			device.DNSResponseCodes[responseCode]++
		}
		if isResponse && responseDomain != "" {
			device.DNSResponseDomains[responseDomain]++
		}
		if !isResponse && queryDomain != "" {
			device.RecentDNSQueries[queryDomain] = time.Now()
		} else if l7Info != "" {
			device.RecentDNSQueries[l7Info] = time.Now()
		}
	}
	if mode := nm.identifyEncryptedDNS(evt.EventType, evt.SrcPort, evt.DstPort, srcIP, dstIP); mode != "" {
		device.EncryptedDNS[mode]++
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
		if evt.EventType != models.EVENT_TYPE_DNS && evt.EventType != models.EVENT_TYPE_ARP && evt.EventType != models.EVENT_TYPE_ICMP {
			if domain := nm.pickRecentDNSDomain(device, time.Now(), 2*time.Minute); domain != "" {
				device.DNSCorrelated++
				device.CorrelatedDomains[domain]++
			}
		}

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
	nm.evaluateAlerts(device)
	nm.checkSecurityBaselines(device, evt, srcIP, trafficType)
	nm.anomaly.observe(time.Now(), evt, srcMAC)

	// Notify if new device
	// TODO: add to syslog or alerting system
	if isNew {
		select {
		case nm.newDeviceChan <- device:
		default:
		}
	}
}

func (nm *NetworkMonitor) GetAnomalySnapshot() models.AnomalySnapshot {
	if nm.anomaly == nil {
		return models.AnomalySnapshot{Status: "disabled"}
	}
	return nm.anomaly.status()
}

func (nm *NetworkMonitor) checkSecurityBaselines(device *models.DeviceInfo, evt *models.NetworkEvent, srcIP string, trafficType models.TrafficType) {
	if nm.baselines == nil || device == nil {
		return
	}
	switch {
	case trafficType == models.TrafficUDPDHCP:
		nm.baselines.checkDHCP(nm, device, evt, srcIP)
	case evt.EventType == models.EVENT_TYPE_ICMP && evt.IsIPv6 == 1:
		nm.baselines.checkRA(nm, device, evt, srcIP)
	case evt.EventType == models.EVENT_TYPE_ARP:
		nm.baselines.checkARP(nm, device, evt, srcIP)
	}
}

func (nm *NetworkMonitor) evaluateAlerts(device *models.DeviceInfo) {
	if device == nil {
		return
	}
	nm.fireAlertIfNeeded(device, "dns_query_volume", device.DNSQueries > nm.alertConfig.MaxDNSQueriesPerDevice,
		"high", fmt.Sprintf("DNS queries exceeded threshold (%d > %d)", device.DNSQueries, nm.alertConfig.MaxDNSQueriesPerDevice))
	nm.fireAlertIfNeeded(device, "tcp_connection_volume", device.TCPConnections > nm.alertConfig.MaxTCPConnections,
		"high", fmt.Sprintf("TCP connections exceeded threshold (%d > %d)", device.TCPConnections, nm.alertConfig.MaxTCPConnections))
	nm.fireAlertIfNeeded(device, "target_spread", len(device.Targets) > nm.alertConfig.MaxUniqueTargets,
		"medium", fmt.Sprintf("Unique targets exceeded threshold (%d > %d)", len(device.Targets), nm.alertConfig.MaxUniqueTargets))
}

func (nm *NetworkMonitor) fireAlertIfNeeded(device *models.DeviceInfo, rule string, triggered bool, severity, message string) {
	key := fmt.Sprintf("%s|%s", device.MAC, rule)
	if triggered {
		if nm.alertRuleState[key] {
			return
		}
		nm.alertRuleState[key] = true
		alert := models.AlertEvent{
			ID:         fmt.Sprintf("%d-%s-%s", time.Now().UnixNano(), device.MAC, rule),
			DeviceMAC:  device.MAC,
			DeviceIP:   device.IP,
			Vendor:     device.Vendor,
			Rule:       rule,
			Severity:   severity,
			Message:    message,
			ObservedAt: time.Now(),
		}
		nm.alerts = append(nm.alerts, alert)
		if len(nm.alerts) > 500 {
			nm.alerts = nm.alerts[len(nm.alerts)-500:]
		}
		return
	}
	delete(nm.alertRuleState, key)
}

func (nm *NetworkMonitor) GetAlerts() []models.AlertEvent {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	out := make([]models.AlertEvent, len(nm.alerts))
	copy(out, nm.alerts)
	return out
}

func (nm *NetworkMonitor) pickRecentDNSDomain(device *models.DeviceInfo, now time.Time, ttl time.Duration) string {
	var latestDomain string
	var latestTime time.Time
	for domain, seenAt := range device.RecentDNSQueries {
		if now.Sub(seenAt) > ttl {
			delete(device.RecentDNSQueries, domain)
			continue
		}
		if latestDomain == "" || seenAt.After(latestTime) {
			latestDomain = domain
			latestTime = seenAt
		}
	}
	return latestDomain
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
	if nm.ouiDB == nil {
		return "Unknown"
	}
	return nm.ouiDB.Lookup(mac)
}

// SnapshotPacketStats returns a copy of aggregate packet counters (reads under nm.mu.RLock).
func (nm *NetworkMonitor) SnapshotPacketStats() map[string]uint64 {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return map[string]uint64{
		"total": nm.Stats.TotalPackets,
		"arp":   nm.Stats.ArpPackets,
		"tcp":   nm.Stats.TcpPackets,
		"udp":   nm.Stats.UdpPackets,
		"icmp":  nm.Stats.IcmpPackets,
		"dns":   nm.Stats.DnsPackets,
		"http":  nm.Stats.HttpPackets,
		"tls":   nm.Stats.TlsPackets,
	}
}

// GetStats returns a deep copy of each device suitable for concurrent JSON encoding or printing.
// Live cache entries are mutated by TrackEvent; callers must not retain pointers across unlock.
func (nm *NetworkMonitor) GetStats() map[string]*models.DeviceInfo {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	stats := make(map[string]*models.DeviceInfo)
	for _, mac := range nm.Cache.Keys() {
		if device, ok := nm.Cache.Get(mac); ok {
			stats[mac] = cloneDeviceInfo(device)
		}
	}
	return stats
}

func cloneStringIntMap(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneTrafficTypeIntMap(m map[models.TrafficType]int) map[models.TrafficType]int {
	if m == nil {
		return nil
	}
	out := make(map[models.TrafficType]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneDeviceInfo(d *models.DeviceInfo) *models.DeviceInfo {
	if d == nil {
		return nil
	}
	c := *d
	c.Targets = append([]string(nil), d.Targets...)
	c.Services = cloneStringIntMap(d.Services)
	c.DNSDomains = cloneStringIntMap(d.DNSDomains)
	c.DNSResponseDomains = cloneStringIntMap(d.DNSResponseDomains)
	c.DNSQueryTypes = cloneStringIntMap(d.DNSQueryTypes)
	c.DNSResponseCodes = cloneStringIntMap(d.DNSResponseCodes)
	c.EncryptedDNS = cloneStringIntMap(d.EncryptedDNS)
	c.CorrelatedDomains = cloneStringIntMap(d.CorrelatedDomains)
	c.HTTPHosts = cloneStringIntMap(d.HTTPHosts)
	c.TLSSNIs = cloneStringIntMap(d.TLSSNIs)
	c.TLSVersions = cloneStringIntMap(d.TLSVersions)
	c.TrafficTypeCounts = cloneTrafficTypeIntMap(d.TrafficTypeCounts)
	c.RecentDNSQueries = nil
	c.SeenPatterns = nil
	c.FlowStats = nil
	return &c
}

func (nm *NetworkMonitor) PrintStats() {
	stats := nm.GetStats()
	pkt := nm.SnapshotPacketStats()

	fmt.Printf("\n╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║              NETWORK STATISTICS SUMMARY                       ║\n")
	fmt.Printf("╠═══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Total Devices: %-46d ║\n", len(stats))
	fmt.Printf("║ Total Packets: %-46d ║\n", pkt["total"])
	fmt.Printf("║   - ARP:  %-51d ║\n", pkt["arp"])
	fmt.Printf("║   - TCP:  %-51d ║\n", pkt["tcp"])
	fmt.Printf("║   - UDP:  %-51d ║\n", pkt["udp"])
	fmt.Printf("║   - ICMP: %-51d ║\n", pkt["icmp"])
	fmt.Printf("║   - DNS:  %-51d ║\n", pkt["dns"])
	fmt.Printf("║   - HTTP: %-51d ║\n", pkt["http"])
	fmt.Printf("║   - TLS:  %-51d ║\n", pkt["tls"])
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
