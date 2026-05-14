package models

import "time"

type TrafficType string

const (
	L7PayloadSize = 128
	EventSize     = 208
)

const (
	EVENT_TYPE_ARP  = 1
	EVENT_TYPE_TCP  = 2
	EVENT_TYPE_UDP  = 3
	EVENT_TYPE_ICMP = 4
	EVENT_TYPE_DNS  = 5
	EVENT_TYPE_HTTP = 6
	EVENT_TYPE_TLS  = 7
)

const (
	// ARP Traffic
	TrafficARPRequest  TrafficType = "ARP_REQUEST"
	TrafficARPReply    TrafficType = "ARP_REPLY"
	TrafficARPProbe    TrafficType = "ARP_PROBE"
	TrafficARPAnnounce TrafficType = "ARP_ANNOUNCE"
	TrafficARPScan     TrafficType = "ARP_SCAN"

	// TCP Traffic
	TrafficTCPSYN    TrafficType = "TCP_SYN"
	TrafficTCPSYNACK TrafficType = "TCP_SYNACK"
	TrafficTCPACK    TrafficType = "TCP_ACK"
	TrafficTCPFIN    TrafficType = "TCP_FIN"
	TrafficTCPRST    TrafficType = "TCP_RST"
	TrafficTCPHTTP   TrafficType = "TCP_HTTP"
	TrafficTCPHTTPS  TrafficType = "TCP_HTTPS"
	TrafficTCPSSH    TrafficType = "TCP_SSH"
	TrafficTCPCustom TrafficType = "TCP_CUSTOM"

	// UDP Traffic
	TrafficUDPDNS    TrafficType = "UDP_DNS"
	TrafficUDPDHCP   TrafficType = "UDP_DHCP"
	TrafficUDPNTP    TrafficType = "UDP_NTP"
	TrafficUDPSNMP   TrafficType = "UDP_SNMP"
	TrafficUDPCustom TrafficType = "UDP_CUSTOM"

	// ICMP Traffic
	TrafficICMPEchoRequest  TrafficType = "ICMP_ECHO_REQUEST"
	TrafficICMPEchoReply    TrafficType = "ICMP_ECHO_REPLY"
	TrafficICMPDestUnreach  TrafficType = "ICMP_DEST_UNREACHABLE"
	TrafficICMPTimeExceeded TrafficType = "ICMP_TIME_EXCEEDED"
	TrafficICMPRedirect     TrafficType = "ICMP_REDIRECT"
	TrafficICMPCustom       TrafficType = "ICMP_CUSTOM"

	// DNS Traffic
	TrafficDNSQuery    TrafficType = "DNS_QUERY"
	TrafficDNSResponse TrafficType = "DNS_RESPONSE"

	// HTTP Traffic
	TrafficHTTPGET     TrafficType = "HTTP_GET"
	TrafficHTTPPOST    TrafficType = "HTTP_POST"
	TrafficHTTPRequest TrafficType = "HTTP_REQUEST"

	// TLS Traffic
	TrafficTLSClientHello TrafficType = "TLS_CLIENT_HELLO"
	TrafficTLSServerHello TrafficType = "TLS_SERVER_HELLO"
	TrafficTLSHandshake   TrafficType = "TLS_HANDSHAKE"

	// Direction
	TrafficLocalToLocal    TrafficType = "LOCAL_TO_LOCAL"
	TrafficLocalToExternal TrafficType = "LOCAL_TO_EXTERNAL"
	TrafficExternalToLocal TrafficType = "EXTERNAL_TO_LOCAL"
)

type NetworkEvent struct {
	EventType uint8
	SrcMac    [6]byte
	DstMac    [6]byte
	SrcIP     uint32
	DstIP     uint32
	IsIPv6    uint8
	SrcIPv6   [16]byte
	DstIPv6   [16]byte
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TCPFlags  uint8
	ArpOp     uint16
	ArpSha    [6]byte
	ArpTha    [6]byte
	ICMPType  uint8
	ICMPCode  uint8
	IfIndex   uint32              // Interface index
	L7Payload [L7PayloadSize]byte // First bytes of payload for L7 inspection
}

type ServiceInfo struct {
	Port        uint16
	Protocol    string
	Service     string
	Description string
}

type CommunicationPattern struct {
	SrcMAC      string      `json:"src_mac"`
	SrcIP       string      `json:"src_ip"`
	DstIP       string      `json:"dst_ip"`
	DstPort     uint16      `json:"dst_port"`
	Protocol    string      `json:"protocol"`
	TrafficType TrafficType `json:"traffic_type"`
	Service     string      `json:"service"`
	Timestamp   time.Time   `json:"timestamp"`
	L7Info      string      `json:"l7_info,omitempty"`   // DNS domain, HTTP path, TLS SNI, etc.
	Interface   string      `json:"interface,omitempty"` // Network interface name (e.g., eth0, wlan0)
}

type FlowStats struct {
	PacketCount int       `json:"packet_count"`
	ByteCount   int       `json:"byte_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type AlertRuleConfig struct {
	MaxDNSQueriesPerDevice int `json:"max_dns_queries_per_device"`
	MaxTCPConnections      int `json:"max_tcp_connections"`
	MaxUniqueTargets       int `json:"max_unique_targets"`
	// KnownGoodDHCPServers seeds the rogue-DHCP baseline with legitimate server IPs
	// (HA pairs, dual-stack routers). Any DHCP reply from a source not in this list
	// and not the first-seen server triggers a rogue_dhcp_server alert.
	KnownGoodDHCPServers []string `json:"known_good_dhcp_servers,omitempty"`
	// KnownGoodRARouters seeds the rogue-RA baseline with legitimate IPv6 router
	// link-local addresses. Same first-seen-wins logic as DHCP otherwise.
	KnownGoodRARouters []string `json:"known_good_ra_routers,omitempty"`
}

type AlertEvent struct {
	ID         string    `json:"id"`
	DeviceMAC  string    `json:"device_mac"`
	DeviceIP   string    `json:"device_ip"`
	Vendor     string    `json:"vendor"`
	Rule       string    `json:"rule"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	ObservedAt time.Time `json:"observed_at"`
}

type AnomalyFeatures struct {
	PacketRate        float64 `json:"packet_rate"`
	DNSRate           float64 `json:"dns_rate"`
	HTTPRate          float64 `json:"http_rate"`
	TLSRate           float64 `json:"tls_rate"`
	TCPSynRate        float64 `json:"tcp_syn_rate"`
	UniqueDeviceCount float64 `json:"unique_device_count"`
	UnusualPortCount  float64 `json:"unusual_port_count"`
	PortEntropy       float64 `json:"port_entropy"`
	PacketRateSlope   float64 `json:"packet_rate_slope"`
}

// AnomalyContribution explains one feature’s deviation from the learned baseline.
type AnomalyContribution struct {
	Feature        string  `json:"feature"`
	Label          string  `json:"label"`
	Value          float64 `json:"value"`
	BaselineMedian float64 `json:"baseline_median"`
	RobustZ        float64 `json:"robust_z"`
}

type AnomalyAlert struct {
	ObservedAt time.Time `json:"observed_at"`
	Score      float64   `json:"score"`
	Severity   string    `json:"severity"`
	Reason     string    `json:"reason"`
	// Summary is plain-language (“why this looks unusual”).
	Summary string `json:"summary"`
	// Detail is the technical breakdown (medians, robust σ, etc.).
	Detail   string          `json:"detail,omitempty"`
	Features AnomalyFeatures `json:"features"`
	// Contributions sorted by impact (largest robust_z first).
	Contributions []AnomalyContribution `json:"contributions"`
}

type AnomalySnapshot struct {
	WindowSeconds      int             `json:"window_seconds"`
	Status             string          `json:"status"`
	BaselineWindows    int             `json:"baseline_windows"`
	CurrentScore       float64         `json:"current_score"`
	RobustZScore       float64         `json:"robust_z_score"`
	CentroidDistance   float64         `json:"centroid_distance"`
	IsAnomaly          bool            `json:"is_anomaly"`
	RecentAnomalyCount int             `json:"recent_anomaly_count"`
	LastFeatures       AnomalyFeatures `json:"last_features"`
	LastEvaluatedAt    time.Time       `json:"last_evaluated_at"`
	// Plain-language readout for the most recent scored window.
	LastSummary string `json:"last_summary,omitempty"`
	// LastSummaryDetail is the technical paragraph for the same window (medians, σ).
	LastSummaryDetail string                `json:"last_summary_detail,omitempty"`
	LastContributions []AnomalyContribution `json:"last_contributions,omitempty"`
	RecentAlerts      []AnomalyAlert        `json:"recent_alerts"`
}

type DeviceInfo struct {
	MAC            string `json:"mac"`
	IP             string `json:"ip"`
	Vendor         string `json:"vendor"`
	GeoCountry     string `json:"geo_country,omitempty"`
	GeoCountryCode string `json:"geo_country_code,omitempty"`
	GeoCity        string `json:"geo_city,omitempty"`
	Interface      string `json:"interface,omitempty"` // Network interface name (e.g., eth0, wlan0)
	// IsGateway is true once we observe this MAC sourcing IPv4 packets whose
	// L3 source IP is outside any local subnet, i.e. forwarded/NATed traffic.
	IsGateway bool `json:"is_gateway,omitempty"`
	// ForwardedSourceCount counts non-ARP IPv4 packets seen from this MAC
	// whose source IP is not on a local subnet. A non-zero value implies the
	// device is acting as a router/NAT, not the originator of those packets.
	ForwardedSourceCount int                   `json:"forwarded_source_count,omitempty"`
	FirstSeen            time.Time             `json:"first_seen"`
	LastSeen             time.Time             `json:"last_seen"`
	RequestCount         int                   `json:"request_count"`
	ReplyCount           int                   `json:"reply_count"`
	TCPConnections       int                   `json:"tcp_connections"`
	UDPConnections       int                   `json:"udp_connections"`
	ICMPPackets          int                   `json:"icmp_packets"`
	DNSQueries           int                   `json:"dns_queries"`
	HTTPRequests         int                   `json:"http_requests"`
	TLSConnections       int                   `json:"tls_connections"`
	Targets              []string              `json:"targets"`
	Services             map[string]int        `json:"services"` // service -> count
	DNSDomains           map[string]int        `json:"dns_domains,omitempty"`
	DNSResponseDomains   map[string]int        `json:"dns_response_domains,omitempty"`
	DNSQueryTypes        map[string]int        `json:"dns_query_types,omitempty"`
	DNSResponseCodes     map[string]int        `json:"dns_response_codes,omitempty"`
	EncryptedDNS         map[string]int        `json:"encrypted_dns,omitempty"`
	DNSCorrelated        int                   `json:"dns_correlated_connections,omitempty"`
	CorrelatedDomains    map[string]int        `json:"correlated_domains,omitempty"`
	HTTPHosts            map[string]int        `json:"http_hosts,omitempty"`
	TLSSNIs              map[string]int        `json:"tls_snis,omitempty"`
	TLSVersions          map[string]int        `json:"tls_versions,omitempty"`
	RecentDNSQueries     map[string]time.Time  `json:"-"`
	SeenPatterns         map[string]bool       `json:"-"`
	TrafficTypeCounts    map[TrafficType]int   `json:"traffic_type_counts"`
	FlowStats            map[string]*FlowStats `json:"-"` // flowKey -> stats
}
