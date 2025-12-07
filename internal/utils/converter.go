package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/zrougamed/cerberus/internal/models"
)

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ParseNetworkEvent(data []byte) *models.NetworkEvent {
	evt := &models.NetworkEvent{}
	offset := 0

	// Event type (1 byte)
	evt.EventType = data[offset]
	offset += 1

	// Source MAC (6 bytes)
	copy(evt.SrcMac[:], data[offset:offset+6])
	offset += 6

	// Destination MAC (6 bytes)
	copy(evt.DstMac[:], data[offset:offset+6])
	offset += 6

	// Source IP (4 bytes)
	evt.SrcIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Destination IP (4 bytes)
	evt.DstIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Source Port (2 bytes)
	evt.SrcPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Destination Port (2 bytes)
	evt.DstPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Protocol (1 byte)
	evt.Protocol = data[offset]
	offset += 1

	// TCP Flags (1 byte)
	evt.TCPFlags = data[offset]
	offset += 1

	// ARP Operation (2 bytes)
	evt.ArpOp = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// ARP SHA (6 bytes)
	copy(evt.ArpSha[:], data[offset:offset+6])
	offset += 6

	// ARP THA (6 bytes)
	copy(evt.ArpTha[:], data[offset:offset+6])
	offset += 6

	// ICMP Type (1 byte)
	evt.ICMPType = data[offset]
	offset += 1

	// ICMP Code (1 byte)
	evt.ICMPCode = data[offset]
	offset += 1

	// L7 Payload (32 bytes)
	if len(data) >= offset+32 {
		copy(evt.L7Payload[:], data[offset:offset+32])
	}

	return evt
}

func IntToIP(i uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b)
}

func MacToString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// InspectDNS extracts domain name from DNS query/response payload
func InspectDNS(payload [32]byte) string {
	// Simple DNS query name extraction
	// DNS query format: [transaction_id(2)][flags(2)][questions(2)][answers(2)][authority(2)][additional(2)][query...]
	if len(payload) < 13 {
		return ""
	}

	// Skip DNS header (12 bytes) and parse QNAME
	offset := 12
	var domain []string

	for offset < len(payload) {
		labelLen := int(payload[offset])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || offset+labelLen+1 > len(payload) {
			break
		}

		offset++
		label := string(payload[offset : offset+labelLen])
		domain = append(domain, label)
		offset += labelLen
	}

	if len(domain) > 0 {
		return strings.Join(domain, ".")
	}
	return ""
}

// InspectHTTP extracts HTTP method and path from payload
func InspectHTTP(payload [32]byte) (method string, path string) {
	str := string(payload[:])

	// Check for HTTP methods
	if strings.HasPrefix(str, "GET ") {
		method = "GET"
		parts := strings.Fields(str)
		if len(parts) >= 2 {
			path = parts[1]
		}
	} else if strings.HasPrefix(str, "POST ") {
		method = "POST"
		parts := strings.Fields(str)
		if len(parts) >= 2 {
			path = parts[1]
		}
	} else if strings.HasPrefix(str, "HEAD ") {
		method = "HEAD"
		parts := strings.Fields(str)
		if len(parts) >= 2 {
			path = parts[1]
		}
	} else if strings.HasPrefix(str, "PUT ") {
		method = "PUT"
		parts := strings.Fields(str)
		if len(parts) >= 2 {
			path = parts[1]
		}
	} else if strings.HasPrefix(str, "DELETE ") {
		method = "DELETE"
		parts := strings.Fields(str)
		if len(parts) >= 2 {
			path = parts[1]
		}
	}

	return method, path
}

// InspectTLS extracts SNI from TLS Client Hello
func InspectTLS(payload [32]byte) string {
	// TLS Client Hello starts with: 0x16 (handshake), 0x03 0x01/0x03 (version)
	if len(payload) < 5 {
		return ""
	}

	if payload[0] != 0x16 {
		return ""
	}

	// Simple SNI extraction would require parsing the full TLS handshake
	// TODO: Full SNI parsing requires more than 32 bytes typically

	return "TLS"
}

// GetL7Info extracts layer 7 information based on event type and payload
func GetL7Info(evt *models.NetworkEvent) string {
	switch evt.EventType {
	case models.EVENT_TYPE_DNS:
		if domain := InspectDNS(evt.L7Payload); domain != "" {
			return domain
		}
	case models.EVENT_TYPE_HTTP:
		method, path := InspectHTTP(evt.L7Payload)
		if method != "" {
			if path != "" {
				return fmt.Sprintf("%s %s", method, path)
			}
			return method
		}
	case models.EVENT_TYPE_TLS:
		return InspectTLS(evt.L7Payload)
	}
	return ""
}
