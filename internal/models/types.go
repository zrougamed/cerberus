package models

import "time"

type TrafficType string

const (
	EVENT_TYPE_ARP = 1
	EVENT_TYPE_TCP = 2
	EVENT_TYPE_UDP = 3
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
	Targets           []string              `json:"targets"`
	Services          map[string]int        `json:"services"` // service -> count
	SeenPatterns      map[string]bool       `json:"-"`
	TrafficTypeCounts map[TrafficType]int   `json:"traffic_type_counts"`
	FlowStats         map[string]*FlowStats `json:"-"` // flowKey -> stats
}
