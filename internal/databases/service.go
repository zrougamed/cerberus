package databases

import "github.com/zrougamed/cerberus/internal/models"

// TODO: Expand this database or load from external source
func LoadServiceDatabase() map[uint16]*models.ServiceInfo {
	return map[uint16]*models.ServiceInfo{
		20:    {20, "TCP", "FTP-DATA", "File Transfer Protocol (Data)"},
		21:    {21, "TCP", "FTP", "File Transfer Protocol (Control)"},
		22:    {22, "TCP", "SSH", "Secure Shell"},
		23:    {23, "TCP", "TELNET", "Telnet"},
		25:    {25, "TCP", "SMTP", "Simple Mail Transfer Protocol"},
		53:    {53, "UDP", "DNS", "Domain Name System"},
		67:    {67, "UDP", "DHCP-SERVER", "DHCP Server"},
		68:    {68, "UDP", "DHCP-CLIENT", "DHCP Client"},
		80:    {80, "TCP", "HTTP", "Hypertext Transfer Protocol"},
		110:   {110, "TCP", "POP3", "Post Office Protocol v3"},
		123:   {123, "UDP", "NTP", "Network Time Protocol"},
		143:   {143, "TCP", "IMAP", "Internet Message Access Protocol"},
		161:   {161, "UDP", "SNMP", "Simple Network Management Protocol"},
		162:   {162, "UDP", "SNMP-TRAP", "SNMP Trap"},
		443:   {443, "TCP", "HTTPS", "HTTP over TLS/SSL"},
		445:   {445, "TCP", "SMB", "Server Message Block"},
		514:   {514, "UDP", "SYSLOG", "System Logging"},
		1194:  {1194, "UDP", "OPENVPN", "OpenVPN"},
		1883:  {1883, "TCP", "MQTT", "Message Queuing Telemetry Transport"},
		3306:  {3306, "TCP", "MYSQL", "MySQL Database"},
		3389:  {3389, "TCP", "RDP", "Remote Desktop Protocol"},
		5432:  {5432, "TCP", "POSTGRESQL", "PostgreSQL Database"},
		5672:  {5672, "TCP", "AMQP", "Advanced Message Queuing Protocol"},
		6379:  {6379, "TCP", "REDIS", "Redis Database"},
		8080:  {8080, "TCP", "HTTP-ALT", "HTTP Alternate"},
		8443:  {8443, "TCP", "HTTPS-ALT", "HTTPS Alternate"},
		9200:  {9200, "TCP", "ELASTICSEARCH", "Elasticsearch"},
		27017: {27017, "TCP", "MONGODB", "MongoDB Database"},
	}
}
