package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/zrougamed/cerberus/internal/models"
)

func Contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ParseNetworkEvent(data []byte) *models.NetworkEvent {
	evt := &models.NetworkEvent{}
	if len(data) < models.EventSize {
		return evt
	}
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

	// IPv6 marker and addresses
	evt.IsIPv6 = data[offset]
	offset += 1
	copy(evt.SrcIPv6[:], data[offset:offset+16])
	offset += 16
	copy(evt.DstIPv6[:], data[offset:offset+16])
	offset += 16

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

	// Interface Index (4 bytes)
	evt.IfIndex = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// L7 Payload
	if len(data) >= offset+models.L7PayloadSize {
		copy(evt.L7Payload[:], data[offset:offset+models.L7PayloadSize])
	}

	return evt
}

func IntToIP(i uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b)
}

func IPv6BytesToString(ip [16]byte) string {
	return net.IP(ip[:]).String()
}

func EventSrcIPString(evt *models.NetworkEvent) string {
	if evt != nil && evt.IsIPv6 == 1 {
		return IPv6BytesToString(evt.SrcIPv6)
	}
	return IntToIP(evt.SrcIP).String()
}

func EventDstIPString(evt *models.NetworkEvent) string {
	if evt != nil && evt.IsIPv6 == 1 {
		return IPv6BytesToString(evt.DstIPv6)
	}
	return IntToIP(evt.DstIP).String()
}

func MacToString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// IfIndexToName converts an interface index to its name (e.g., "eth0")
func IfIndexToName(ifindex uint32) string {
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return fmt.Sprintf("if%d", ifindex)
	}
	return iface.Name
}

// InspectDNS extracts domain name from DNS query/response payload
func InspectDNS(payload [models.L7PayloadSize]byte) string {
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
func InspectHTTP(payload [models.L7PayloadSize]byte) (method string, path string) {
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

func ExtractHTTPHost(payload [models.L7PayloadSize]byte) string {
	raw := string(payload[:])
	raw = strings.Trim(raw, "\x00")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return ""
	}
	first := strings.TrimSpace(strings.TrimSuffix(lines[0], "\r"))
	if first == "" {
		return ""
	}
	isHTTP := strings.HasPrefix(first, "GET ") ||
		strings.HasPrefix(first, "POST ") ||
		strings.HasPrefix(first, "PUT ") ||
		strings.HasPrefix(first, "DELETE ") ||
		strings.HasPrefix(first, "HEAD ") ||
		strings.HasPrefix(first, "PATCH ") ||
		strings.HasPrefix(first, "OPTIONS ")
	if !isHTTP {
		return ""
	}
	for _, line := range lines[1:] {
		l := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.EqualFold(l, "") {
			break
		}
		if idx := strings.Index(l, ":"); idx > 0 {
			key := strings.TrimSpace(l[:idx])
			if strings.EqualFold(key, "Host") {
				return strings.TrimSpace(l[idx+1:])
			}
		}
	}
	return ""
}

func DNSQueryTypeName(queryType uint16) string {
	switch queryType {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE_%d", queryType)
	}
}

func DNSRCodeName(rcode uint8) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", rcode)
	}
}

func parseDNSName(payload []byte, offset int) (name string, nextOffset int, ok bool) {
	if offset >= len(payload) {
		return "", offset, false
	}
	labels := make([]string, 0, 6)
	cur := offset
	jumped := false
	jumpLimit := 8
	for cur < len(payload) && jumpLimit > 0 {
		length := int(payload[cur])
		if length == 0 {
			if jumped {
				return strings.Join(labels, "."), nextOffset, true
			}
			cur++
			return strings.Join(labels, "."), cur, true
		}
		// compression pointer: 11xxxxxx xxxxxxxx
		if length&0xC0 == 0xC0 {
			if cur+1 >= len(payload) {
				return "", offset, false
			}
			ptr := int(binary.BigEndian.Uint16(payload[cur:cur+2]) & 0x3FFF)
			if ptr >= len(payload) {
				return "", offset, false
			}
			if !jumped {
				nextOffset = cur + 2
			}
			cur = ptr
			jumped = true
			jumpLimit--
			continue
		}
		if length > 63 || cur+1+length > len(payload) {
			return "", offset, false
		}
		label := string(payload[cur+1 : cur+1+length])
		labels = append(labels, label)
		cur += 1 + length
	}
	if jumped {
		return strings.Join(labels, "."), nextOffset, len(labels) > 0
	}
	return "", offset, false
}

func InspectDNSDetails(payload [models.L7PayloadSize]byte) (domain, queryType, responseCode, responseDomain string, isResponse bool) {
	if len(payload) < 12 {
		return "", "", "", "", false
	}

	flags := uint16(payload[2])<<8 | uint16(payload[3])
	isResponse = flags&0x8000 != 0
	responseCode = DNSRCodeName(uint8(flags & 0x000F))
	qdCount := int(binary.BigEndian.Uint16(payload[4:6]))
	anCount := int(binary.BigEndian.Uint16(payload[6:8]))
	wire := payload[:]

	offset := 12
	if qdCount > 0 {
		parsedDomain, next, ok := parseDNSName(wire, offset)
		if ok {
			domain = parsedDomain
			offset = next
			if offset+4 <= len(wire) {
				qtype := binary.BigEndian.Uint16(wire[offset : offset+2])
				queryType = DNSQueryTypeName(qtype)
				offset += 4
			}
		}
	}
	if isResponse && anCount > 0 {
		for range anCount {
			ansName, next, ok := parseDNSName(wire, offset)
			if !ok || next+10 > len(wire) {
				break
			}
			typ := binary.BigEndian.Uint16(wire[next : next+2])
			rdLen := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
			rdataStart := next + 10
			rdataEnd := rdataStart + rdLen
			if rdataEnd > len(wire) {
				break
			}
			if responseDomain == "" {
				// Prefer CNAME target for richer response parsing.
				if typ == 5 {
					if cname, _, ok := parseDNSName(wire, rdataStart); ok && cname != "" {
						responseDomain = cname
					}
				}
				if responseDomain == "" && ansName != "" {
					responseDomain = ansName
				}
			}
			offset = rdataEnd
		}
	}
	return domain, queryType, responseCode, responseDomain, isResponse
}

// InspectTLS extracts SNI from TLS Client Hello
func InspectTLS(payload [models.L7PayloadSize]byte) string {
	// TLS Client Hello starts with: 0x16 (handshake), 0x03 0x01/0x03 (version)
	if len(payload) < 5 {
		return ""
	}

	if payload[0] != 0x16 {
		return ""
	}

	// Simple SNI extraction would require parsing the full TLS handshake
	// TODO: Full SNI parsing may require deeper handshake parsing.

	if version := TLSVersionFromPayload(payload); version != "" {
		return version
	}
	return "TLS"
}

func TLSVersionFromPayload(payload [models.L7PayloadSize]byte) string {
	if len(payload) < 3 {
		return ""
	}
	if payload[0] != 0x16 {
		return ""
	}
	major := payload[1]
	minor := payload[2]
	if major != 0x03 {
		return ""
	}
	switch minor {
	case 0x00:
		return "SSL 3.0"
	case 0x01:
		return "TLS 1.0"
	case 0x02:
		return "TLS 1.1"
	case 0x03:
		return "TLS 1.2"
	case 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%02x", minor)
	}
}

// IsDHCPServerReply reports whether the payload looks like a BOOTREPLY (op=2),
// which is what DHCP servers send (OFFER, ACK, NAK). Client requests are op=1.
// This is enough to identify a host acting as a DHCP server without parsing options.
func IsDHCPServerReply(payload [models.L7PayloadSize]byte) bool {
	return payload[0] == 2
}

// GetL7Info extracts layer 7 information based on event type and payload
func GetL7Info(evt *models.NetworkEvent) string {
	switch evt.EventType {
	case models.EVENT_TYPE_DNS:
		if domain := InspectDNS(evt.L7Payload); domain != "" {
			return domain
		}
	case models.EVENT_TYPE_HTTP:
		if host := ExtractHTTPHost(evt.L7Payload); host != "" {
			return host
		}
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
