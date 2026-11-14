package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

func TestZonesEndpointAndMetrics(t *testing.T) {
	cfg := alerts.DefaultConfig()
	cfg.Segmentation.Zones = []alerts.Zone{
		{ID: "enterprise", Name: "Enterprise", Level: 4, CIDRs: []string{"10.0.0.0/24"}, Enforce: true},
		{ID: "control", Name: "Control", Level: 1, CIDRs: []string{"10.0.5.0/24"}, Industrial: true},
	}
	mon, err := monitor.NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	// 10.0.0.9 -> 10.0.5.5: enterprise straight to control.
	mon.TrackEvent(&models.NetworkEvent{EventType: models.EVENT_TYPE_TCP, Protocol: 6, SrcMac: [6]byte{2, 0, 0, 0, 0, 1},
		SrcIP: 0x0900000A, DstIP: 0x0505000A, SrcPort: 50000, DstPort: 502, TCPFlags: 0x02})

	h, err := NewServer(mon).Handler()
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil))
	var got monitor.ZoneSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Zones) != 2 || got.Zones[0].ID != "enterprise" || got.Zones[0].Devices != 1 || got.Violations["enterprise>control"] != 1 {
		t.Fatalf("zones = %+v", got)
	}
	if got.Zones[1].Enforce || !got.Zones[1].Industrial {
		t.Fatalf("control zone = %+v", got.Zones[1])
	}

	scrape := httptest.NewRecorder()
	h.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `cerberus_zone_violations_total{from="enterprise",to="control"} 1`) {
		t.Fatalf("metric missing:\n%s", scrape.Body)
	}
}
