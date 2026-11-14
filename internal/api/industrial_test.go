package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

func modbusTCPEvent(srcMAC byte, srcIP, dstIP uint32, sport, dport uint16, pdu ...byte) *models.NetworkEvent {
	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_TCP,
		Protocol:  6,
		SrcMac:    [6]byte{0x02, 0, 0, 0, 0, srcMAC},
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   sport,
		DstPort:   dport,
	}
	copy(evt.L7Payload[:], append([]byte{0, 1, 0, 0, 0, byte(len(pdu) + 1), 1}, pdu...))
	return evt
}

func TestIndustrial_MetricsAndDeviceJSON(t *testing.T) {
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = mon.Close() })

	// 10.0.0.9 -> 10.0.0.5, stored as the TC program stores them.
	client, plc := uint32(0x0900000A), uint32(0x0500000A)
	mon.TrackEvent(modbusTCPEvent(1, client, plc, 50000, 502, 0x03, 0, 0, 0, 1))
	mon.TrackEvent(modbusTCPEvent(1, client, plc, 50000, 502, 0x03, 0, 0, 0, 1))
	mon.TrackEvent(modbusTCPEvent(1, client, plc, 50000, 502, 0x06, 0, 1, 0, 3))
	mon.TrackEvent(modbusTCPEvent(5, plc, client, 502, 50000, 0x03, 2, 0, 7))

	srv := NewServer(mon)

	rr := httptest.NewRecorder()
	srv.handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE cerberus_industrial_messages_total counter",
		`cerberus_industrial_messages_total{protocol="modbus",class="read",direction="request"} 2`,
		`cerberus_industrial_messages_total{protocol="modbus",class="read",direction="response"} 1`,
		`cerberus_industrial_messages_total{protocol="modbus",class="write",direction="request"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	readReq := strings.Index(body, `class="read",direction="request"`)
	readResp := strings.Index(body, `class="read",direction="response"`)
	write := strings.Index(body, `class="write"`)
	if readReq >= readResp || readResp >= write {
		t.Fatal("industrial series are not in a stable order")
	}

	rr = httptest.NewRecorder()
	srv.handleDevices(rr, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	var devices []models.DeviceInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &devices); err != nil {
		t.Fatalf("decode devices: %v", err)
	}
	byMAC := map[string]models.DeviceInfo{}
	for _, d := range devices {
		byMAC[d.MAC] = d
	}
	c := byMAC["02:00:00:00:00:01"].Industrial["modbus"]
	if c == nil || c.Requests != 3 || c.Operations["write"] != 1 {
		t.Fatalf("client industrial = %+v", c)
	}
	if p := byMAC["02:00:00:00:00:05"].Industrial["modbus"]; p == nil || p.Responses != 1 {
		t.Fatalf("plc industrial = %+v", p)
	}
}

func TestMetrics_NoIndustrialSeriesWithoutTraffic(t *testing.T) {
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	rr := httptest.NewRecorder()
	NewServer(mon).handleMetrics(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rr.Body.String(), "cerberus_industrial_messages_total") {
		t.Fatal("industrial metric emitted with no industrial traffic")
	}
}

func TestCmpBool(t *testing.T) {
	t.Parallel()
	if cmpBool(false, false) != 0 || cmpBool(true, true) != 0 || cmpBool(false, true) != -1 || cmpBool(true, false) != 1 {
		t.Fatal("cmpBool ordering wrong")
	}
}
