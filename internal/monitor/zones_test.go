package monitor

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func zoneMonitor(t *testing.T, mutate func(*alerts.SegmentationConfig)) *NetworkMonitor {
	t.Helper()
	cfg := alerts.DefaultConfig()
	cfg.Segmentation.Zones = []alerts.Zone{
		{ID: "enterprise", Name: "Enterprise", Level: 4, CIDRs: []string{"10.0.0.0/16"}, Enforce: true},
		{ID: "supervisory", Name: "Supervisory", Level: 2, CIDRs: []string{"10.10.0.0/24"}, Enforce: true},
		{ID: "dmz", Name: "DMZ", Level: 3, CIDRs: []string{"10.30.0.0/24"}, Enforce: true},
		{ID: "control", Name: "Control", Level: 1, CIDRs: []string{"10.20.0.0/24"}, Industrial: true},
	}
	cfg.Segmentation.Conduits = []alerts.Conduit{{From: "supervisory", To: "control", Ports: []int{502}}}
	if mutate != nil {
		mutate(&cfg.Segmentation)
	}
	nm, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	return nm
}

func tcpEvent(mac byte, src, dst string, sport, dport uint16, flags uint8) *models.NetworkEvent {
	evt := modbusEvent(mac, src, dst, sport, dport, 0)
	evt.L7Payload = [models.L7PayloadSize]byte{}
	evt.TCPFlags = flags
	return evt
}

func zoneAlerts(nm *NetworkMonitor) []models.AlertEvent {
	var out []models.AlertEvent
	for _, a := range nm.GetAlerts() {
		if a.Rule == alerts.RuleZoneNoConduit || a.Rule == alerts.RuleZoneLevelSkip {
			out = append(out, a)
		}
	}
	return out
}

func TestZones_ConduitAllowsPollAndReply(t *testing.T) {
	nm := zoneMonitor(t, nil)
	nm.TrackEvent(tcpEvent(1, "10.10.0.5", "10.20.0.50", 50000, 502, 0x02))
	nm.TrackEvent(tcpEvent(2, "10.20.0.50", "10.10.0.5", 502, 50000, 0x12))
	if got := zoneAlerts(nm); len(got) != 0 {
		t.Fatalf("alerts = %+v", got)
	}
	if nm.GetStats()["02:00:00:00:00:01"].Zone != "supervisory" || nm.GetStats()["02:00:00:00:00:02"].Zone != "control" {
		t.Fatal("device zones not recorded")
	}
}

func TestZones_NoConduitAndLevelSkip(t *testing.T) {
	nm := zoneMonitor(t, nil)
	nm.TrackEvent(tcpEvent(1, "10.10.0.5", "10.20.0.50", 50000, 22, 0x02))  // adjacent levels, wrong port
	nm.TrackEvent(tcpEvent(3, "10.0.4.7", "10.20.0.50", 51000, 502, 0x02))  // enterprise -> control
	nm.TrackEvent(tcpEvent(3, "10.0.4.7", "10.20.0.50", 51000, 502, 0x10))  // same pair, inside window
	nm.TrackEvent(tcpEvent(2, "10.20.0.50", "10.10.0.5", 50001, 502, 0x02)) // plc opens a connection
	icmp := tcpEvent(3, "10.0.4.7", "10.30.0.9", 0, 0, 0)
	icmp.EventType, icmp.Protocol = models.EVENT_TYPE_ICMP, 1
	nm.TrackEvent(icmp) // enterprise -> dmz, adjacent, no conduit

	got := map[string][]models.AlertEvent{}
	for _, a := range zoneAlerts(nm) {
		got[a.Rule] = append(got[a.Rule], a)
	}
	if len(got[alerts.RuleZoneLevelSkip]) != 1 || len(got[alerts.RuleZoneNoConduit]) != 3 {
		t.Fatalf("alerts = %+v", got)
	}
	skip := got[alerts.RuleZoneLevelSkip][0]
	if want := "No conduit for TCP 10.0.4.7:51000 -> 10.20.0.50:502 from Enterprise (level 4) to Control (level 1), skips 2 levels"; skip.Message != want || skip.Severity != "high" {
		t.Fatalf("skip alert = %+v", skip)
	}
	found := false
	for _, a := range got[alerts.RuleZoneNoConduit] {
		found = found || a.Message == "No conduit for ICMP 10.0.4.7 -> 10.30.0.9 from Enterprise (level 4) to DMZ (level 3)"
	}
	if !found {
		t.Fatalf("icmp alert missing: %+v", got[alerts.RuleZoneNoConduit])
	}
	s := nm.GetZoneSummary()
	if s.Violations["enterprise>control"] != 2 || s.Violations["supervisory>control"] != 1 || s.Violations["control>supervisory"] != 1 {
		t.Fatalf("violations = %+v", s.Violations)
	}
}

func TestZones_UnzonedTrafficNotJudged(t *testing.T) {
	nm := zoneMonitor(t, nil)
	nm.TrackEvent(tcpEvent(1, "10.20.0.50", "8.8.8.8", 50000, 443, 0x02))
	nm.TrackEvent(tcpEvent(4, "192.168.1.9", "10.20.0.50", 50000, 502, 0x02))
	if got := zoneAlerts(nm); len(got) != 0 {
		t.Fatalf("alerts = %+v", got)
	}
	if nm.GetStats()["02:00:00:00:00:04"].Zone != "" {
		t.Fatal("unzoned device got a zone")
	}
}

func TestZones_DisabledRulesAndRealert(t *testing.T) {
	nm := zoneMonitor(t, func(s *alerts.SegmentationConfig) {
		s.LevelSkip.Enabled = false
		s.NoConduit.RealertSeconds = 60
	})
	d := &models.DeviceInfo{MAC: "02:00:00:00:00:03", IP: "10.0.4.7"}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	nm.mu.Lock()
	nm.checkZones(d, tcpEvent(3, "10.0.4.7", "10.20.0.50", 1, 502, 0x02), "10.0.4.7", "10.20.0.50", "TCP", t0) // skip: disabled
	nm.checkZones(d, tcpEvent(3, "10.0.4.7", "10.30.0.9", 1, 80, 0x02), "10.0.4.7", "10.30.0.9", "TCP", t0)
	nm.checkZones(d, tcpEvent(3, "10.0.4.7", "10.30.0.9", 1, 80, 0x02), "10.0.4.7", "10.30.0.9", "TCP", t0.Add(30*time.Second))
	nm.checkZones(d, tcpEvent(3, "10.0.4.7", "10.30.0.9", 1, 80, 0x02), "10.0.4.7", "10.30.0.9", "TCP", t0.Add(2*time.Minute))
	nm.mu.Unlock()
	if got := zoneAlerts(nm); len(got) != 2 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestZones_PruneAtCap(t *testing.T) {
	nm := zoneMonitor(t, nil)
	now := time.Now()
	for i := range maxZoneAlertKeys {
		nm.zoneLast[fmt.Sprintf("k%d", i)] = now.Add(-2 * time.Hour)
	}
	nm.pruneZoneState(now)
	if len(nm.zoneLast) != 0 {
		t.Fatalf("expired keys kept: %d", len(nm.zoneLast))
	}
	for i := range maxZoneAlertKeys {
		nm.zoneLast[fmt.Sprintf("k%d", i)] = now
	}
	nm.pruneZoneState(now)
	if len(nm.zoneLast) != 0 {
		t.Fatal("state not reset at cap")
	}
}

func TestZoneSummary(t *testing.T) {
	nm := zoneMonitor(t, nil)
	nm.TrackEvent(tcpEvent(2, "10.20.0.50", "10.10.0.5", 502, 50000, 0x12))
	s := nm.GetZoneSummary()
	if len(s.Zones) != 4 || len(s.Conduits) != 1 {
		t.Fatalf("summary = %+v", s)
	}
	for _, z := range s.Zones {
		if (z.ID == "control") != (z.Devices == 1) {
			t.Fatalf("zone %s devices = %d", z.ID, z.Devices)
		}
	}
	plain := newIndustrialMonitor(t, nil)
	if s := plain.GetZoneSummary(); len(s.Zones) != 0 || s.Violations == nil {
		t.Fatalf("no-zone summary = %+v", s)
	}
}

func TestZones_InvalidConfigRefusesToStart(t *testing.T) {
	cfg := alerts.DefaultConfig()
	cfg.Segmentation.Zones = []alerts.Zone{{ID: "x", Level: 1, CIDRs: []string{"nope"}}}
	if _, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg); err == nil {
		t.Fatal("invalid segmentation accepted")
	}
}
