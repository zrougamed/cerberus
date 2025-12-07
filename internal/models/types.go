package models

import "time"

type TrafficType string

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
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TCPFlags  uint8
	ArpOp     uint16
	ArpSha    [6]byte
	ArpTha    [6]byte
	ICMPType  uint8
	ICMPCode  uint8
	L7Payload [32]byte // First 32 bytes of payload for L7 inspection
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
	L7Info      string      `json:"l7_info,omitempty"` // DNS domain, HTTP path, TLS SNI, etc.
}

type FlowStats struct {
	PacketCount int       `json:"packet_count"`
	ByteCount   int       `json:"byte_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type DeviceInfo struct {
	MAC               string                `json:"mac"`
	IP                string                `json:"ip"`
	Vendor            string                `json:"vendor"`
	FirstSeen         time.Time             `json:"first_seen"`
	LastSeen          time.Time             `json:"last_seen"`
	RequestCount      int                   `json:"request_count"`
	ReplyCount        int                   `json:"reply_count"`
	TCPConnections    int                   `json:"tcp_connections"`
	UDPConnections    int                   `json:"udp_connections"`
	ICMPPackets       int                   `json:"icmp_packets"`
	DNSQueries        int                   `json:"dns_queries"`
	HTTPRequests      int                   `json:"http_requests"`
	TLSConnections    int                   `json:"tls_connections"`
	Targets           []string              `json:"targets"`
	Services          map[string]int        `json:"services"` // service -> count
	DNSDomains        map[string]int        `json:"dns_domains,omitempty"`
	HTTPHosts         map[string]int        `json:"http_hosts,omitempty"`
	TLSSNIs           map[string]int        `json:"tls_snis,omitempty"`
	SeenPatterns      map[string]bool       `json:"-"`
	TrafficTypeCounts map[TrafficType]int   `json:"traffic_type_counts"`
	FlowStats         map[string]*FlowStats `json:"-"` // flowKey -> stats
}
