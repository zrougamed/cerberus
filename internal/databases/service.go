package databases

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/models"
)

// ServiceDatabase represents a comprehensive service/port lookup system
type ServiceDatabase struct {
	services       map[uint16]*models.ServiceInfo
	tcpServices    map[uint16]*models.ServiceInfo
	udpServices    map[uint16]*models.ServiceInfo
	threatPorts    map[uint16]ThreatInfo
	mu             sync.RWMutex
	dbPath         string
	lastSync       time.Time
	threatListPath string
}

// ThreatInfo contains security information about dangerous ports
type ThreatInfo struct {
	Port        uint16
	Protocol    string
	ThreatLevel string // "HIGH", "MEDIUM", "LOW"
	Category    string // "MALWARE", "BACKDOOR", "BOTNET", "SCANNING", "EXPLOIT"
	Description string
	CVEs        []string
}

const (
	// IANA Service Names and Port Numbers
	IANA_SERVICES_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

	// Local cache settings
	SERVICES_CACHE_FILE = "iana_services.csv"
	THREATS_CACHE_FILE  = "threat_ports.txt"
	SERVICES_CACHE_DAYS = 90 // Refresh every 90 days
)

// NewServiceDatabase creates a comprehensive service database
func NewServiceDatabase(enableOnline bool) (*ServiceDatabase, error) {
	db := &ServiceDatabase{
		services:       make(map[uint16]*models.ServiceInfo),
		tcpServices:    make(map[uint16]*models.ServiceInfo),
		udpServices:    make(map[uint16]*models.ServiceInfo),
		threatPorts:    make(map[uint16]ThreatInfo),
		dbPath:         filepath.Join(CACHE_DIR, SERVICES_CACHE_FILE),
		threatListPath: filepath.Join(CACHE_DIR, THREATS_CACHE_FILE),
	}

	// Load threat intelligence database
	db.loadThreatDatabase()

	// Try to load from cache
	if err := db.loadFromCache(); err != nil {
		if enableOnline {
			// Download from IANA
			if err := db.downloadIANADatabase(); err != nil {
				// Fallback to comprehensive hardcoded list
				db.loadFallbackDatabase()
			}
		} else {
			// Offline mode
			db.loadFallbackDatabase()
		}
	}

	return db, nil
}

// LoadServiceDatabase returns basic map for backward compatibility
func LoadServiceDatabase() map[uint16]*models.ServiceInfo {
	db, _ := NewServiceDatabase(false)
	return db.services
}

// downloadIANADatabase downloads the official IANA service registry
func (db *ServiceDatabase) downloadIANADatabase() error {
	fmt.Println("Downloading IANA service registry...")

	if err := os.MkdirAll(CACHE_DIR, 0755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(IANA_SERVICES_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Save to cache
	cacheFile, err := os.Create(db.dbPath)
	if err != nil {
		return err
	}
	defer cacheFile.Close()

	// Parse CSV format
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Write to cache
	if _, err := cacheFile.Write(body); err != nil {
		return err
	}

	// Parse the CSV
	count := db.parseIANACSV(string(body))
	db.lastSync = time.Now()

	fmt.Printf("Successfully loaded %d services from IANA registry\n", count)
	return nil
}

// loadFromCache loads services from local cache
func (db *ServiceDatabase) loadFromCache() error {
	fileInfo, err := os.Stat(db.dbPath)
	if err != nil {
		return fmt.Errorf("cache not found: %w", err)
	}

	if time.Since(fileInfo.ModTime()) > SERVICES_CACHE_DAYS*24*time.Hour {
		return fmt.Errorf("cache outdated")
	}

	data, err := os.ReadFile(db.dbPath)
	if err != nil {
		return err
	}

	count := db.parseIANACSV(string(data))
	db.lastSync = fileInfo.ModTime()

	fmt.Printf("Loaded %d services from cache (age: %s)\n",
		count, time.Since(fileInfo.ModTime()).Round(24*time.Hour))

	return nil
}

// parseIANACSV parses IANA CSV format
func (db *ServiceDatabase) parseIANACSV(data string) int {
	lines := strings.Split(data, "\n")
	count := 0

	for i, line := range lines {
		if i == 0 || line == "" {
			continue // Skip header
		}

		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		serviceName := strings.TrimSpace(fields[0])
		portRange := strings.TrimSpace(fields[1])
		protocol := strings.ToUpper(strings.TrimSpace(fields[2]))
		description := strings.TrimSpace(fields[3])

		// Parse port (skip ranges for now)
		if strings.Contains(portRange, "-") {
			continue
		}

		port, err := strconv.ParseUint(portRange, 10, 16)
		if err != nil || port == 0 || port > 65535 {
			continue
		}

		portNum := uint16(port)

		service := &models.ServiceInfo{
			Port:        portNum,
			Protocol:    protocol,
			Service:     strings.ToUpper(serviceName),
			Description: description,
		}

		db.mu.Lock()
		if protocol == "TCP" {
			db.tcpServices[portNum] = service
		} else if protocol == "UDP" {
			db.udpServices[portNum] = service
		}
		db.services[portNum] = service
		db.mu.Unlock()

		count++
	}

	return count
}

// loadFallbackDatabase loads comprehensive hardcoded database
func (db *ServiceDatabase) loadFallbackDatabase() {
	fallback := map[uint16]*models.ServiceInfo{
		// File Transfer
		20:  {Port: 20, Protocol: "TCP", Service: "FTP-DATA", Description: "File Transfer Protocol (Data)"},
		21:  {Port: 21, Protocol: "TCP", Service: "FTP", Description: "File Transfer Protocol (Control)"},
		69:  {Port: 69, Protocol: "UDP", Service: "TFTP", Description: "Trivial File Transfer Protocol"},
		989: {Port: 989, Protocol: "TCP", Service: "FTPS-DATA", Description: "FTP over TLS/SSL (Data)"},
		990: {Port: 990, Protocol: "TCP", Service: "FTPS", Description: "FTP over TLS/SSL (Control)"},

		// Remote Access
		22:   {Port: 22, Protocol: "TCP", Service: "SSH", Description: "Secure Shell"},
		23:   {Port: 23, Protocol: "TCP", Service: "TELNET", Description: "Telnet"},
		3389: {Port: 3389, Protocol: "TCP", Service: "RDP", Description: "Remote Desktop Protocol"},
		5900: {Port: 5900, Protocol: "TCP", Service: "VNC", Description: "Virtual Network Computing"},
		5901: {Port: 5901, Protocol: "TCP", Service: "VNC-1", Description: "VNC Display 1"},

		// Email
		25:  {Port: 25, Protocol: "TCP", Service: "SMTP", Description: "Simple Mail Transfer Protocol"},
		110: {Port: 110, Protocol: "TCP", Service: "POP3", Description: "Post Office Protocol v3"},
		143: {Port: 143, Protocol: "TCP", Service: "IMAP", Description: "Internet Message Access Protocol"},
		465: {Port: 465, Protocol: "TCP", Service: "SMTPS", Description: "SMTP over TLS/SSL"},
		587: {Port: 587, Protocol: "TCP", Service: "SUBMISSION", Description: "Email Message Submission"},
		993: {Port: 993, Protocol: "TCP", Service: "IMAPS", Description: "IMAP over TLS/SSL"},
		995: {Port: 995, Protocol: "TCP", Service: "POP3S", Description: "POP3 over TLS/SSL"},

		// Web
		80:   {Port: 80, Protocol: "TCP", Service: "HTTP", Description: "Hypertext Transfer Protocol"},
		443:  {Port: 443, Protocol: "TCP", Service: "HTTPS", Description: "HTTP over TLS/SSL"},
		8000: {Port: 8000, Protocol: "TCP", Service: "HTTP-ALT", Description: "HTTP Alternate"},
		8080: {Port: 8080, Protocol: "TCP", Service: "HTTP-PROXY", Description: "HTTP Proxy"},
		8443: {Port: 8443, Protocol: "TCP", Service: "HTTPS-ALT", Description: "HTTPS Alternate"},
		8888: {Port: 8888, Protocol: "TCP", Service: "HTTP-ALT2", Description: "HTTP Alternate 2"},

		// DNS & Network Services
		53:  {Port: 53, Protocol: "UDP", Service: "DNS", Description: "Domain Name System"},
		67:  {Port: 67, Protocol: "UDP", Service: "DHCP-SERVER", Description: "DHCP Server"},
		68:  {Port: 68, Protocol: "UDP", Service: "DHCP-CLIENT", Description: "DHCP Client"},
		123: {Port: 123, Protocol: "UDP", Service: "NTP", Description: "Network Time Protocol"},
		514: {Port: 514, Protocol: "UDP", Service: "SYSLOG", Description: "System Logging"},
		520: {Port: 520, Protocol: "UDP", Service: "RIP", Description: "Routing Information Protocol"},

		// File Sharing
		137:  {Port: 137, Protocol: "UDP", Service: "NETBIOS-NS", Description: "NetBIOS Name Service"},
		138:  {Port: 138, Protocol: "UDP", Service: "NETBIOS-DGM", Description: "NetBIOS Datagram Service"},
		139:  {Port: 139, Protocol: "TCP", Service: "NETBIOS-SSN", Description: "NetBIOS Session Service"},
		445:  {Port: 445, Protocol: "TCP", Service: "SMB", Description: "Server Message Block"},
		2049: {Port: 2049, Protocol: "TCP", Service: "NFS", Description: "Network File System"},

		// Databases
		1433:  {Port: 1433, Protocol: "TCP", Service: "MSSQL", Description: "Microsoft SQL Server"},
		1521:  {Port: 1521, Protocol: "TCP", Service: "ORACLE", Description: "Oracle Database"},
		3306:  {Port: 3306, Protocol: "TCP", Service: "MYSQL", Description: "MySQL Database"},
		5432:  {Port: 5432, Protocol: "TCP", Service: "POSTGRESQL", Description: "PostgreSQL Database"},
		6379:  {Port: 6379, Protocol: "TCP", Service: "REDIS", Description: "Redis Database"},
		27017: {Port: 27017, Protocol: "TCP", Service: "MONGODB", Description: "MongoDB Database"},
		9200:  {Port: 9200, Protocol: "TCP", Service: "ELASTICSEARCH", Description: "Elasticsearch"},
		9300:  {Port: 9300, Protocol: "TCP", Service: "ELASTICSEARCH-CLUSTER", Description: "Elasticsearch Cluster"},

		// Message Queues
		1883: {Port: 1883, Protocol: "TCP", Service: "MQTT", Description: "Message Queuing Telemetry Transport"},
		5672: {Port: 5672, Protocol: "TCP", Service: "AMQP", Description: "Advanced Message Queuing Protocol"},
		9092: {Port: 9092, Protocol: "TCP", Service: "KAFKA", Description: "Apache Kafka"},
		4222: {Port: 4222, Protocol: "TCP", Service: "NATS", Description: "NATS Messaging"},

		// VPN & Tunneling
		500:  {Port: 500, Protocol: "UDP", Service: "ISAKMP", Description: "Internet Security Association and Key Management Protocol"},
		1194: {Port: 1194, Protocol: "UDP", Service: "OPENVPN", Description: "OpenVPN"},
		1701: {Port: 1701, Protocol: "UDP", Service: "L2TP", Description: "Layer 2 Tunneling Protocol"},
		1723: {Port: 1723, Protocol: "TCP", Service: "PPTP", Description: "Point-to-Point Tunneling Protocol"},
		4500: {Port: 4500, Protocol: "UDP", Service: "IPSEC-NAT-T", Description: "IPsec NAT Traversal"},

		// Directory Services
		389: {Port: 389, Protocol: "TCP", Service: "LDAP", Description: "Lightweight Directory Access Protocol"},
		636: {Port: 636, Protocol: "TCP", Service: "LDAPS", Description: "LDAP over TLS/SSL"},
		88:  {Port: 88, Protocol: "TCP", Service: "KERBEROS", Description: "Kerberos Authentication"},

		// Monitoring & Management
		161:  {Port: 161, Protocol: "UDP", Service: "SNMP", Description: "Simple Network Management Protocol"},
		162:  {Port: 162, Protocol: "UDP", Service: "SNMP-TRAP", Description: "SNMP Trap"},
		9090: {Port: 9090, Protocol: "TCP", Service: "PROMETHEUS", Description: "Prometheus Monitoring"},
		9093: {Port: 9093, Protocol: "TCP", Service: "ALERTMANAGER", Description: "Prometheus Alertmanager"},
		8086: {Port: 8086, Protocol: "TCP", Service: "INFLUXDB", Description: "InfluxDB Time Series Database"},

		// Container & Orchestration
		2375:  {Port: 2375, Protocol: "TCP", Service: "DOCKER", Description: "Docker REST API (unencrypted)"},
		2376:  {Port: 2376, Protocol: "TCP", Service: "DOCKER-TLS", Description: "Docker REST API (TLS)"},
		6443:  {Port: 6443, Protocol: "TCP", Service: "KUBERNETES", Description: "Kubernetes API Server"},
		8001:  {Port: 8001, Protocol: "TCP", Service: "KUBERNETES-PROXY", Description: "Kubernetes API Proxy"},
		10250: {Port: 10250, Protocol: "TCP", Service: "KUBELET", Description: "Kubernetes Kubelet API"},

		// Game Servers
		25565: {Port: 25565, Protocol: "TCP", Service: "MINECRAFT", Description: "Minecraft Server"},
		27015: {Port: 27015, Protocol: "UDP", Service: "STEAM", Description: "Steam Game Server"},
		3074:  {Port: 3074, Protocol: "UDP", Service: "XBOX-LIVE", Description: "Xbox Live"},
		7777:  {Port: 7777, Protocol: "UDP", Service: "UNREAL", Description: "Unreal Tournament"},

		// Media Streaming
		554:  {Port: 554, Protocol: "TCP", Service: "RTSP", Description: "Real Time Streaming Protocol"},
		1935: {Port: 1935, Protocol: "TCP", Service: "RTMP", Description: "Real Time Messaging Protocol"},
		5004: {Port: 5004, Protocol: "UDP", Service: "RTP", Description: "Real-time Transport Protocol"},
		8554: {Port: 8554, Protocol: "TCP", Service: "RTSP-ALT", Description: "RTSP Alternate"},

		// IoT Protocols
		8883: {Port: 8883, Protocol: "TCP", Service: "MQTT-TLS", Description: "MQTT over TLS"},
		5683: {Port: 5683, Protocol: "UDP", Service: "COAP", Description: "Constrained Application Protocol"},
		5684: {Port: 5684, Protocol: "UDP", Service: "COAPS", Description: "CoAP over DTLS"},

		// Printing
		515:  {Port: 515, Protocol: "TCP", Service: "LPD", Description: "Line Printer Daemon"},
		631:  {Port: 631, Protocol: "TCP", Service: "IPP", Description: "Internet Printing Protocol"},
		9100: {Port: 9100, Protocol: "TCP", Service: "PDL", Description: "Printer Data Language"},

		// Development
		3000: {Port: 3000, Protocol: "TCP", Service: "DEV-SERVER", Description: "Development Server (React/Node)"},
		4000: {Port: 4000, Protocol: "TCP", Service: "DEV-SERVER-ALT", Description: "Development Server Alt"},
		5000: {Port: 5000, Protocol: "TCP", Service: "FLASK", Description: "Flask Development Server"},
		9229: {Port: 9229, Protocol: "TCP", Service: "NODE-INSPECT", Description: "Node.js Inspector"},

		// Backup & Storage
		873:  {Port: 873, Protocol: "TCP", Service: "RSYNC", Description: "rsync File Synchronization"},
		3260: {Port: 3260, Protocol: "TCP", Service: "ISCSI", Description: "iSCSI Storage"},

		// Proxy & Cache
		3128: {Port: 3128, Protocol: "TCP", Service: "SQUID", Description: "Squid Proxy"},
		8118: {Port: 8118, Protocol: "TCP", Service: "PRIVOXY", Description: "Privoxy Proxy"},
		9050: {Port: 9050, Protocol: "TCP", Service: "TOR-SOCKS", Description: "Tor SOCKS Proxy"},

		// Version Control
		9418: {Port: 9418, Protocol: "TCP", Service: "GIT", Description: "Git Protocol"},
		3690: {Port: 3690, Protocol: "TCP", Service: "SVN", Description: "Subversion"},

		// Analytics & Search
		5601: {Port: 5601, Protocol: "TCP", Service: "KIBANA", Description: "Kibana"},
		8983: {Port: 8983, Protocol: "TCP", Service: "SOLR", Description: "Apache Solr"},
	}

	db.mu.Lock()
	// Split into TCP/UDP maps
	for port, svc := range fallback {
		switch svc.Protocol {
		case "TCP":
			db.tcpServices[port] = svc
		case "UDP":
			db.udpServices[port] = svc
		}
	}

	db.mu.Unlock()

	fmt.Printf("Using fallback database with %d services\n", len(fallback))
}

// loadThreatDatabase loads known dangerous ports
func (db *ServiceDatabase) loadThreatDatabase() {
	threats := map[uint16]ThreatInfo{
		// Malware & Backdoors
		31337: {31337, "TCP", "HIGH", "BACKDOOR", "Back Orifice trojan", []string{}},
		12345: {12345, "TCP", "HIGH", "BACKDOOR", "NetBus trojan", []string{}},
		1337:  {1337, "TCP", "MEDIUM", "BACKDOOR", "Common backdoor port", []string{}},
		6666:  {6666, "TCP", "MEDIUM", "BACKDOOR", "IRC-based backdoors", []string{}},

		// Botnets
		6667: {6667, "TCP", "MEDIUM", "BOTNET", "IRC C&C channel", []string{}},
		6668: {6668, "TCP", "MEDIUM", "BOTNET", "IRC C&C alternate", []string{}},
		7777: {7777, "TCP", "MEDIUM", "BOTNET", "Zeus botnet C&C", []string{}},

		// Ransomware
		4444: {4444, "TCP", "HIGH", "MALWARE", "Metasploit default, ransomware C&C", []string{}},
		8888: {8888, "TCP", "MEDIUM", "MALWARE", "Malware communication", []string{}},

		// Exploits
		135:  {135, "TCP", "HIGH", "EXPLOIT", "MS RPC - EternalBlue", []string{"CVE-2017-0144"}},
		139:  {139, "TCP", "HIGH", "EXPLOIT", "NetBIOS - WannaCry vector", []string{"CVE-2017-0144"}},
		445:  {445, "TCP", "HIGH", "EXPLOIT", "SMB - EternalBlue, NotPetya", []string{"CVE-2017-0144"}},
		3389: {3389, "TCP", "HIGH", "EXPLOIT", "RDP - BlueKeep", []string{"CVE-2019-0708"}},

		// Scanning Indicators
		7:  {7, "TCP", "LOW", "SCANNING", "Echo - port scan indicator", []string{}},
		19: {19, "TCP", "LOW", "SCANNING", "Chargen - DDoS amplification", []string{}},

		// Cryptocurrency Mining
		3333: {3333, "TCP", "MEDIUM", "CRYPTOMINING", "Mining pool connection", []string{}},
		8333: {8333, "TCP", "MEDIUM", "CRYPTOMINING", "Bitcoin node", []string{}},

		// Database Attacks
		1433:  {1433, "TCP", "MEDIUM", "EXPLOIT", "MS SQL - SQL Slammer", []string{}},
		3306:  {3306, "TCP", "MEDIUM", "EXPLOIT", "MySQL - exposed database", []string{}},
		5432:  {5432, "TCP", "MEDIUM", "EXPLOIT", "PostgreSQL - exposed database", []string{}},
		27017: {27017, "TCP", "MEDIUM", "EXPLOIT", "MongoDB - exposed database", []string{}},
		6379:  {6379, "TCP", "MEDIUM", "EXPLOIT", "Redis - exposed cache", []string{}},

		// Docker/Kubernetes Exposure
		2375:  {2375, "TCP", "HIGH", "EXPLOIT", "Docker API unencrypted - remote code execution", []string{}},
		2376:  {2376, "TCP", "MEDIUM", "EXPLOIT", "Docker API encrypted - still risky", []string{}},
		10250: {10250, "TCP", "HIGH", "EXPLOIT", "Kubelet API - cluster compromise", []string{}},
	}

	db.mu.Lock()
	db.threatPorts = threats
	db.mu.Unlock()
}

// Lookup finds service information for a port
func (db *ServiceDatabase) Lookup(port uint16, protocol string) *models.ServiceInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()
	protocol = strings.ToUpper(protocol)

	// Protocol-specific lookup
	switch protocol {
	case "TCP":
		if svc, ok := db.tcpServices[port]; ok {
			return svc
		}
	case "UDP":
		if svc, ok := db.udpServices[port]; ok {
			return svc
		}
	}

	// Fallback to general lookup
	if svc, ok := db.services[port]; ok {
		return svc
	}

	return &models.ServiceInfo{
		Port:        port,
		Protocol:    protocol,
		Service:     fmt.Sprintf("%s/%d", protocol, port),
		Description: "Unknown Service",
	}
}

// GetThreatInfo checks if a port is associated with threats
func (db *ServiceDatabase) GetThreatInfo(port uint16) (ThreatInfo, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	threat, exists := db.threatPorts[port]
	return threat, exists
}

// IsDangerous checks if a port is considered dangerous
func (db *ServiceDatabase) IsDangerous(port uint16) bool {
	_, exists := db.GetThreatInfo(port)
	return exists
}

func (db *ServiceDatabase) GetStats() map[string]any {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]any{
		"total_services": len(db.services),
		"tcp_services":   len(db.tcpServices),
		"udp_services":   len(db.udpServices),
		"threat_ports":   len(db.threatPorts),
		"last_sync":      db.lastSync,
		"cache_age":      time.Since(db.lastSync).Round(24 * time.Hour).String(),
	}
}

// UpdateDatabase forces refresh from IANA
func (db *ServiceDatabase) UpdateDatabase() error {
	return db.downloadIANADatabase()
}
