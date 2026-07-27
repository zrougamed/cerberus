package monitor

import (
	"path/filepath"
	"testing"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func TestEvaluateAlertsRespectsConfig(t *testing.T) {
	cfg := alerts.DefaultConfig()
	for i := range cfg.Thresholds {
		if cfg.Thresholds[i].ID == "dns_query_volume" {
			cfg.Thresholds[i].Value = 50
		}
		if cfg.Thresholds[i].ID == "target_spread" {
			cfg.Thresholds[i].Enabled = false
		}
	}

	dbPath := filepath.Join(t.TempDir(), "t.db")
	nm, err := NewNetworkMonitorWithAlerts(10, dbPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer nm.Close()

	device := &models.DeviceInfo{
		MAC:        "aa:bb:cc:dd:ee:ff",
		DNSQueries: 51,
		Targets:    make([]string, 19),
	}
	nm.evaluateAlerts(device)

	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "dns_query_volume" {
		t.Fatalf("expected only dns_query_volume, got %+v", nm.alerts)
	}
}

func TestNewNetworkMonitorRejectsBadConfig(t *testing.T) {
	cfg := alerts.DefaultConfig()
	cfg.TargetHistorySize = 0
	_, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg)
	if err == nil {
		t.Fatal("expected error for invalid alert config")
	}
}
