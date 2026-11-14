package utils

import (
	"testing"

	"github.com/zrougamed/cerberus/internal/models"
)

func TestExtractHTTPHost(t *testing.T) {
	var payload [models.L7PayloadSize]byte
	copy(payload[:], []byte("GET /health HTTP/1.1\r\nHost: api.local\r\nUser-Agent: t\r\n\r\n"))
	host := ExtractHTTPHost(payload)
	if host != "api.local" {
		t.Fatalf("expected api.local, got %q", host)
	}
}

func TestInspectDNSDetailsQueryAndResponse(t *testing.T) {
	var query [models.L7PayloadSize]byte
	// DNS header: QR=0, one question
	query[2] = 0x01
	query[3] = 0x00
	query[4] = 0x00
	query[5] = 0x01
	// QNAME "a.com"
	query[12] = 1
	query[13] = 'a'
	query[14] = 3
	query[15] = 'c'
	query[16] = 'o'
	query[17] = 'm'
	query[18] = 0
	// QTYPE A
	query[19] = 0
	query[20] = 1
	query[21] = 0
	query[22] = 1 // QCLASS IN

	domain, qtype, rcode, responseDomain, isResp := InspectDNSDetails(query)
	if domain != "a.com" {
		t.Fatalf("expected domain a.com, got %q", domain)
	}
	if qtype != "A" {
		t.Fatalf("expected qtype A, got %q", qtype)
	}
	if rcode != "NOERROR" {
		t.Fatalf("expected rcode NOERROR, got %q", rcode)
	}
	if isResp {
		t.Fatalf("expected query packet")
	}
	if responseDomain != "" {
		t.Fatalf("did not expect responseDomain for query, got %q", responseDomain)
	}

	var response [models.L7PayloadSize]byte
	response[2] = 0x81 // QR=1
	response[3] = 0x83 // RCODE=3 NXDOMAIN
	domain, qtype, rcode, responseDomain, isResp = InspectDNSDetails(response)
	if !isResp {
		t.Fatalf("expected response packet")
	}
	if rcode != "NXDOMAIN" {
		t.Fatalf("expected NXDOMAIN, got %q", rcode)
	}
	if domain != "" || qtype != "" || responseDomain != "" {
		t.Fatalf("expected empty domain/qtype for minimal response payload")
	}
}

func TestInspectDNSDetailsResponseAnswerParsing(t *testing.T) {
	var payload [models.L7PayloadSize]byte
	// Header: response, qd=1, an=1
	payload[2] = 0x81
	payload[3] = 0x80
	payload[4] = 0x00
	payload[5] = 0x01
	payload[6] = 0x00
	payload[7] = 0x01
	// Question: a.com
	payload[12] = 1
	payload[13] = 'a'
	payload[14] = 3
	payload[15] = 'c'
	payload[16] = 'o'
	payload[17] = 'm'
	payload[18] = 0
	payload[19] = 0x00
	payload[20] = 0x01
	payload[21] = 0x00
	payload[22] = 0x01
	// Answer: name pointer to question, type A, class IN, ttl, rdlen=4
	payload[23] = 0xC0
	payload[24] = 0x0C
	payload[25] = 0x00
	payload[26] = 0x01
	payload[27] = 0x00
	payload[28] = 0x01
	payload[29] = 0x00
	payload[30] = 0x00
	payload[31] = 0x00
	payload[32] = 0x3C
	payload[33] = 0x00
	payload[34] = 0x04
	payload[35] = 1
	payload[36] = 2
	payload[37] = 3
	payload[38] = 4

	domain, qtype, rcode, responseDomain, isResp := InspectDNSDetails(payload)
	if !isResp {
		t.Fatalf("expected response packet")
	}
	if domain != "a.com" || qtype != "A" {
		t.Fatalf("unexpected query parsed values: domain=%q qtype=%q", domain, qtype)
	}
	if rcode != "NOERROR" {
		t.Fatalf("expected NOERROR, got %q", rcode)
	}
	if responseDomain != "a.com" {
		t.Fatalf("expected response domain a.com, got %q", responseDomain)
	}
}

func TestInspectTLSExtractsSNI(t *testing.T) {
	hello := buildClientHelloWithSNI("cdn.example.com")
	var payload [models.L7PayloadSize]byte
	copy(payload[:], hello)
	if got := InspectTLS(payload); got != "cdn.example.com" {
		t.Fatalf("expected cdn.example.com, got %q", got)
	}
	var empty [models.L7PayloadSize]byte
	if got := InspectTLS(empty); got != "" {
		t.Fatalf("expected empty SNI, got %q", got)
	}
}

func buildClientHelloWithSNI(host string) []byte {
	// Minimal ClientHello body (after handshake header).
	var body []byte
	body = append(body, 0x03, 0x03) // client_version TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session_id length
	body = append(body, 0, 2, 0x00, 0x2f) // cipher suites: one suite
	body = append(body, 1, 0)          // compression methods

	name := []byte(host)
	serverName := []byte{0, byte(len(name) >> 8), byte(len(name))}
	serverName = append(serverName, name...)
	sniList := []byte{byte((len(serverName)) >> 8), byte(len(serverName))}
	sniList = append(sniList, serverName...)
	ext := []byte{0, 0, byte(len(sniList) >> 8), byte(len(sniList))}
	ext = append(ext, sniList...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestTLSVersionFromPayload(t *testing.T) {
	var tls12 [models.L7PayloadSize]byte
	tls12[0] = 0x16
	tls12[1] = 0x03
	tls12[2] = 0x03
	if got := TLSVersionFromPayload(tls12); got != "TLS 1.2" {
		t.Fatalf("expected TLS 1.2, got %q", got)
	}

	var tls13 [models.L7PayloadSize]byte
	tls13[0] = 0x16
	tls13[1] = 0x03
	tls13[2] = 0x04
	if got := TLSVersionFromPayload(tls13); got != "TLS 1.3" {
		t.Fatalf("expected TLS 1.3, got %q", got)
	}

	var invalid [models.L7PayloadSize]byte
	invalid[0] = 0x17
	if got := TLSVersionFromPayload(invalid); got != "" {
		t.Fatalf("expected empty version for invalid record, got %q", got)
	}
}

func TestEventIPStringIPv6(t *testing.T) {
	evt := &models.NetworkEvent{
		IsIPv6:  1,
		SrcIPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIPv6: [16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11},
	}
	if got := EventSrcIPString(evt); got != "2001:db8::1" {
		t.Fatalf("expected 2001:db8::1, got %q", got)
	}
	if got := EventDstIPString(evt); got != "2606:4700:4700::11" {
		t.Fatalf("expected 2606:4700:4700::11, got %q", got)
	}
}
