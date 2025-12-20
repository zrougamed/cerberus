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
		20:  {20, "TCP", "FTP-DATA", "File Transfer Protocol (Data)"},
		21:  {21, "TCP", "FTP", "File Transfer Protocol (Control)"},
		69:  {69, "UDP", "TFTP", "Trivial File Transfer Protocol"},
		989: {989, "TCP", "FTPS-DATA", "FTP over TLS/SSL (Data)"},
		990: {990, "TCP", "FTPS", "FTP over TLS/SSL (Control)"},

		// Remote Access
		22:   {22, "TCP", "SSH", "Secure Shell"},
		23:   {23, "TCP", "TELNET", "Telnet"},
		3389: {3389, "TCP", "RDP", "Remote Desktop Protocol"},
		5900: {5900, "TCP", "VNC", "Virtual Network Computing"},
		5901: {5901, "TCP", "VNC-1", "VNC Display 1"},

		// Email
		25:  {25, "TCP", "SMTP", "Simple Mail Transfer Protocol"},
		110: {110, "TCP", "POP3", "Post Office Protocol v3"},
		143: {143, "TCP", "IMAP", "Internet Message Access Protocol"},
		465: {465, "TCP", "SMTPS", "SMTP over TLS/SSL"},
		587: {587, "TCP", "SUBMISSION", "Email Message Submission"},
		993: {993, "TCP", "IMAPS", "IMAP over TLS/SSL"},
		995: {995, "TCP", "POP3S", "POP3 over TLS/SSL"},

		// Web
		80:   {80, "TCP", "HTTP", "Hypertext Transfer Protocol"},
		443:  {443, "TCP", "HTTPS", "HTTP over TLS/SSL"},
		8000: {8000, "TCP", "HTTP-ALT", "HTTP Alternate"},
		8080: {8080, "TCP", "HTTP-PROXY", "HTTP Proxy"},
		8443: {8443, "TCP", "HTTPS-ALT", "HTTPS Alternate"},
		8888: {8888, "TCP", "HTTP-ALT2", "HTTP Alternate 2"},

		// DNS & Network Services
		53:  {53, "UDP", "DNS", "Domain Name System"},
		67:  {67, "UDP", "DHCP-SERVER", "DHCP Server"},
		68:  {68, "UDP", "DHCP-CLIENT", "DHCP Client"},
		123: {123, "UDP", "NTP", "Network Time Protocol"},
		514: {514, "UDP", "SYSLOG", "System Logging"},
		520: {520, "UDP", "RIP", "Routing Information Protocol"},

		// File Sharing
		137:  {137, "UDP", "NETBIOS-NS", "NetBIOS Name Service"},
		138:  {138, "UDP", "NETBIOS-DGM", "NetBIOS Datagram Service"},
		139:  {139, "TCP", "NETBIOS-SSN", "NetBIOS Session Service"},
		445:  {445, "TCP", "SMB", "Server Message Block"},
		2049: {2049, "TCP", "NFS", "Network File System"},

		// Databases
		1433:  {1433, "TCP", "MSSQL", "Microsoft SQL Server"},
		1521:  {1521, "TCP", "ORACLE", "Oracle Database"},
		3306:  {3306, "TCP", "MYSQL", "MySQL Database"},
		5432:  {5432, "TCP", "POSTGRESQL", "PostgreSQL Database"},
		6379:  {6379, "TCP", "REDIS", "Redis Database"},
		27017: {27017, "TCP", "MONGODB", "MongoDB Database"},
		9200:  {9200, "TCP", "ELASTICSEARCH", "Elasticsearch"},
		9300:  {9300, "TCP", "ELASTICSEARCH-CLUSTER", "Elasticsearch Cluster"},

		// Message Queues
		1883: {1883, "TCP", "MQTT", "Message Queuing Telemetry Transport"},
		5672: {5672, "TCP", "AMQP", "Advanced Message Queuing Protocol"},
		9092: {9092, "TCP", "KAFKA", "Apache Kafka"},
		4222: {4222, "TCP", "NATS", "NATS Messaging"},

		// VPN & Tunneling
		500:  {500, "UDP", "ISAKMP", "Internet Security Association and Key Management Protocol"},
		1194: {1194, "UDP", "OPENVPN", "OpenVPN"},
		1701: {1701, "UDP", "L2TP", "Layer 2 Tunneling Protocol"},
		1723: {1723, "TCP", "PPTP", "Point-to-Point Tunneling Protocol"},
		4500: {4500, "UDP", "IPSEC-NAT-T", "IPsec NAT Traversal"},

		// Directory Services
		389: {389, "TCP", "LDAP", "Lightweight Directory Access Protocol"},
		636: {636, "TCP", "LDAPS", "LDAP over TLS/SSL"},
		88:  {88, "TCP", "KERBEROS", "Kerberos Authentication"},

		// Monitoring & Management
		161:  {161, "UDP", "SNMP", "Simple Network Management Protocol"},
		162:  {162, "UDP", "SNMP-TRAP", "SNMP Trap"},
		9090: {9090, "TCP", "PROMETHEUS", "Prometheus Monitoring"},
		9093: {9093, "TCP", "ALERTMANAGER", "Prometheus Alertmanager"},
		8086: {8086, "TCP", "INFLUXDB", "InfluxDB Time Series Database"},

		// Container & Orchestration
		2375:  {2375, "TCP", "DOCKER", "Docker REST API (unencrypted)"},
		2376:  {2376, "TCP", "DOCKER-TLS", "Docker REST API (TLS)"},
		6443:  {6443, "TCP", "KUBERNETES", "Kubernetes API Server"},
		8001:  {8001, "TCP", "KUBERNETES-PROXY", "Kubernetes API Proxy"},
		10250: {10250, "TCP", "KUBELET", "Kubernetes Kubelet API"},

		// Game Servers
		25565: {25565, "TCP", "MINECRAFT", "Minecraft Server"},
		27015: {27015, "UDP", "STEAM", "Steam Game Server"},
		3074:  {3074, "UDP", "XBOX-LIVE", "Xbox Live"},
		7777:  {7777, "UDP", "UNREAL", "Unreal Tournament"},

		// Media Streaming
		554:  {554, "TCP", "RTSP", "Real Time Streaming Protocol"},
		1935: {1935, "TCP", "RTMP", "Real Time Messaging Protocol"},
		5004: {5004, "UDP", "RTP", "Real-time Transport Protocol"},
		8554: {8554, "TCP", "RTSP-ALT", "RTSP Alternate"},

		// IoT Protocols
		8883: {8883, "TCP", "MQTT-TLS", "MQTT over TLS"},
		5683: {5683, "UDP", "COAP", "Constrained Application Protocol"},
		5684: {5684, "UDP", "COAPS", "CoAP over DTLS"},

		// Printing
		515:  {515, "TCP", "LPD", "Line Printer Daemon"},
		631:  {631, "TCP", "IPP", "Internet Printing Protocol"},
		9100: {9100, "TCP", "PDL", "Printer Data Language"},

		// Development
		3000: {3000, "TCP", "DEV-SERVER", "Development Server (React/Node)"},
		4000: {4000, "TCP", "DEV-SERVER-ALT", "Development Server Alt"},
		5000: {5000, "TCP", "FLASK", "Flask Development Server"},
		9229: {9229, "TCP", "NODE-INSPECT", "Node.js Inspector"},

		// Backup & Storage
		873:  {873, "TCP", "RSYNC", "rsync File Synchronization"},
		3260: {3260, "TCP", "ISCSI", "iSCSI Storage"},

		// Proxy & Cache
		3128: {3128, "TCP", "SQUID", "Squid Proxy"},
		8118: {8118, "TCP", "PRIVOXY", "Privoxy Proxy"},
		9050: {9050, "TCP", "TOR-SOCKS", "Tor SOCKS Proxy"},

		// Version Control
		9418: {9418, "TCP", "GIT", "Git Protocol"},
		3690: {3690, "TCP", "SVN", "Subversion"},

		// Analytics & Search
		5601: {5601, "TCP", "KIBANA", "Kibana"},
		8983: {8983, "TCP", "SOLR", "Apache Solr"},
	}

	db.mu.Lock()
	db.services = fallback
	// Split into TCP/UDP maps
	for port, svc := range fallback {
		if svc.Protocol == "TCP" {
			db.tcpServices[port] = svc
		} else if svc.Protocol == "UDP" {
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
	if protocol == "TCP" {
		if svc, ok := db.tcpServices[port]; ok {
			return svc
		}
	} else if protocol == "UDP" {
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

// GetStats returns database statistics
func (db *ServiceDatabase) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
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
