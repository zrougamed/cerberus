package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/version"
)

func TestTopMapOrdersAndLimits(t *testing.T) {
	input := map[string]int{
		"http": 8,
		"dns":  11,
		"tls":  4,
		"ssh":  9,
	}

	got := topMap(input, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got["dns"] != 11 {
		t.Fatalf("expected dns to be kept")
	}
	if got["ssh"] != 9 {
		t.Fatalf("expected ssh to be kept")
	}
	if _, exists := got["tls"]; exists {
		t.Fatalf("did not expect tls in top 2")
	}
}

func TestEscapeLabelValue(t *testing.T) {
	got := escapeLabelValue("Acme \"Corp\"\\line")
	want := "Acme \\\"Corp\\\"\\\\line"
	if got != want {
		t.Fatalf("unexpected escaped label: got %q want %q", got, want)
	}
}

func TestMetricsEndpointIncludesCoreCounters(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	mon, err := monitor.NewNetworkMonitor(10, dbPath)
	if err != nil {
		t.Fatalf("failed to create monitor: %v", err)
	}
	defer func() {
		_ = mon.Close()
		_ = os.Remove(dbPath)
	}()

	mon.Stats.TotalPackets = 12
	mon.Stats.DnsPackets = 4
	now := time.Now()
	mon.Cache.Add("aa:bb:cc:dd:ee:ff", &models.DeviceInfo{
		MAC:            "aa:bb:cc:dd:ee:ff",
		Vendor:         `Acme "Corp"`,
		LastSeen:       now,
		FirstSeen:      now,
		DNSQueries:     3,
		HTTPRequests:   1,
		TLSConnections: 2,
		TCPConnections: 5,
		UDPConnections: 3,
		ICMPPackets:    0,
		TLSVersions: map[string]int{
			"TLS 1.3": 2,
		},
		EncryptedDNS: map[string]int{
			"dot": 1,
			"doh": 2,
		},
		DNSCorrelated: 2,
		CorrelatedDomains: map[string]int{
			"example.com": 2,
		},
	})

	srv := NewServer(mon)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	srv.handleMetrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	mustContain := []string{
		`cerberus_build_info{commit=`,
		`cerberus_packets_total{protocol="total"} 12`,
		`cerberus_packets_total{protocol="dns"} 4`,
		`cerberus_devices_total 1`,
		`cerberus_device_protocol_events_total{mac="aa:bb:cc:dd:ee:ff",vendor="Acme \"Corp\"",protocol="dns"} 3`,
		`cerberus_tls_versions_total{version="TLS 1.3"} 2`,
		`cerberus_encrypted_dns_total{mac="aa:bb:cc:dd:ee:ff",mode="dot"} 1`,
		`cerberus_encrypted_dns_total{mac="aa:bb:cc:dd:ee:ff",mode="doh"} 2`,
		`cerberus_dns_correlated_connections_total{mac="aa:bb:cc:dd:ee:ff"} 2`,
		`cerberus_dns_correlated_connections_total{mac="aa:bb:cc:dd:ee:ff",domain="example.com"} 2`,
	}
	for _, token := range mustContain {
		if !strings.Contains(body, token) {
			t.Fatalf("metrics body missing token %q", token)
		}
	}
}

func TestAlertsEndpointReturnsRecentAlertsFirst(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	mon, err := monitor.NewNetworkMonitor(10, dbPath)
	if err != nil {
		t.Fatalf("failed to create monitor: %v", err)
	}
	defer func() {
		_ = mon.Close()
		_ = os.Remove(dbPath)
	}()

	for i := 0; i < 201; i++ {
		mon.TrackEvent(&models.NetworkEvent{
			EventType: models.EVENT_TYPE_DNS,
			SrcMac:    [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
			SrcIP:     0xC0A8010A, // 192.168.1.10
			DstIP:     0x08080808, // 8.8.8.8
			DstPort:   53,
		})
	}
	time.Sleep(2 * time.Millisecond)
	for i := 0; i < 501; i++ {
		mon.TrackEvent(&models.NetworkEvent{
			EventType: models.EVENT_TYPE_TCP,
			SrcMac:    [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
			SrcIP:     0xC0A80114, // 192.168.1.20
			DstIP:     0x01010101, // 1.1.1.1
			DstPort:   443,
			TCPFlags:  0x02,
		})
	}

	srv := NewServer(mon)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	rr := httptest.NewRecorder()
	srv.handleAlerts(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var out []models.AlertEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected alerts response to contain items")
	}
	if len(out) < 2 {
		t.Fatalf("expected at least two alerts, got %d", len(out))
	}
	if out[0].Rule != "tcp_connection_volume" {
		t.Fatalf("expected most recent alert to be tcp_connection_volume, got %q", out[0].Rule)
	}
	if out[1].Rule != "dns_query_volume" {
		t.Fatalf("expected second alert to be dns_query_volume, got %q", out[1].Rule)
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].ObservedAt.Before(out[i].ObservedAt) {
			t.Fatalf("expected alerts in descending order by observed_at")
		}
	}
}

func TestVersionEndpointReturnsBuildInfo(t *testing.T) {
	prevCommit, prevDate := version.Commit, version.Date
	version.Commit = "abc1234"
	version.Date = "2026-05-14T12:00:00Z"
	t.Cleanup(func() {
		version.Commit = prevCommit
		version.Date = prevDate
	})

	dbPath := filepath.Join(t.TempDir(), "test.db")
	mon, err := monitor.NewNetworkMonitor(10, dbPath)
	if err != nil {
		t.Fatalf("failed to create monitor: %v", err)
	}
	defer func() {
		_ = mon.Close()
		_ = os.Remove(dbPath)
	}()

	srv := NewServer(mon)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rr := httptest.NewRecorder()
	srv.handleVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out version.Info
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if out.Commit != "abc1234" || out.Date != "2026-05-14T12:00:00Z" {
		t.Fatalf("unexpected version payload: %+v", out)
	}
}

func TestAnomaliesEndpointReturnsSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	mon, err := monitor.NewNetworkMonitor(10, dbPath)
	if err != nil {
		t.Fatalf("failed to create monitor: %v", err)
	}
	defer func() {
		_ = mon.Close()
		_ = os.Remove(dbPath)
	}()
	srv := NewServer(mon)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anomalies", nil)
	rr := httptest.NewRecorder()
	srv.handleAnomalies(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out models.AnomalySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if out.WindowSeconds <= 0 {
		t.Fatalf("expected positive window size, got %d", out.WindowSeconds)
	}
}
