package alerts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/models"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestParseOverlayDisableTargetSpread(t *testing.T) {
	yaml := []byte(`
thresholds:
  - id: target_spread
    enabled: false
`)
	cfg, err := Parse(yaml, ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range cfg.Thresholds {
		if r.ID == "target_spread" {
			found = true
			if r.Enabled {
				t.Fatal("expected target_spread disabled")
			}
			if r.Value != 18 {
				t.Fatalf("expected default value kept, got %v", r.Value)
			}
		}
		if r.ID == "dns_query_volume" && !r.Enabled {
			t.Fatal("dns_query_volume should remain enabled")
		}
	}
	if !found {
		t.Fatal("target_spread missing")
	}
}

func TestParseRaiseThresholdAndHistory(t *testing.T) {
	yaml := []byte(`
target_history_size: 40
thresholds:
  - id: target_spread
    value: 30
`)
	cfg, err := Parse(yaml, ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TargetHistorySize != 40 {
		t.Fatalf("history size: got %d", cfg.TargetHistorySize)
	}
	for _, r := range cfg.Thresholds {
		if r.ID == "target_spread" && r.Value != 30 {
			t.Fatalf("value: got %v", r.Value)
		}
	}
}

func TestParseRejectsUnreachableTargetSpread(t *testing.T) {
	yaml := []byte(`
target_history_size: 20
thresholds:
  - id: target_spread
    value: 20
`)
	_, err := Parse(yaml, ".yaml")
	if err == nil {
		t.Fatal("expected validation error when value >= history size")
	}
}

func TestParseRejectsUnknownMetric(t *testing.T) {
	yaml := []byte(`
thresholds:
  - id: weird
    metric: not_a_metric
    op: gt
    value: 1
    severity: low
`)
	_, err := Parse(yaml, ".yaml")
	if err == nil {
		t.Fatal("expected unknown metric error")
	}
}

func TestParseJSON(t *testing.T) {
	data := []byte(`{"anomaly":{"enabled":false}}`)
	cfg, err := Parse(data, ".json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Anomaly.Enabled {
		t.Fatal("expected anomaly disabled")
	}
	if cfg.Anomaly.ScoreThreshold != 3.5 {
		t.Fatalf("expected default score kept, got %v", cfg.Anomaly.ScoreThreshold)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.yaml")
	content := []byte(`
baselines:
  rogue_dhcp_server:
    enabled: true
    known_good: ["192.168.1.1"]
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Baselines.RogueDHCPServer.KnownGood) != 1 || cfg.Baselines.RogueDHCPServer.KnownGood[0] != "192.168.1.1" {
		t.Fatalf("known_good: %+v", cfg.Baselines.RogueDHCPServer.KnownGood)
	}
}

func TestEvaluateThresholds(t *testing.T) {
	cfg := DefaultConfig()
	device := &models.DeviceInfo{
		DNSQueries:     250,
		TCPConnections: 10,
		Targets:        make([]string, 19),
	}
	results := EvaluateThresholds(cfg, device)
	triggered := map[string]bool{}
	for _, r := range results {
		triggered[r.Rule.ID] = r.Triggered
	}
	if !triggered["dns_query_volume"] {
		t.Fatal("expected dns_query_volume triggered")
	}
	if triggered["tcp_connection_volume"] {
		t.Fatal("tcp should not trigger")
	}
	if !triggered["target_spread"] {
		t.Fatal("expected target_spread triggered (19 > 18)")
	}
}

func TestEvaluateSkipsDisabled(t *testing.T) {
	cfg := DefaultConfig()
	for i := range cfg.Thresholds {
		if cfg.Thresholds[i].ID == "dns_query_volume" {
			cfg.Thresholds[i].Enabled = false
		}
	}
	device := &models.DeviceInfo{DNSQueries: 999}
	for _, r := range EvaluateThresholds(cfg, device) {
		if r.Rule.ID == "dns_query_volume" {
			t.Fatal("disabled rule should be skipped")
		}
	}
}

func TestAllExampleConfigFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "configs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("configs directory not found from test cwd")
	}
	var checked int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "alerts.") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		checked++
		path := filepath.Join(dir, name)
		cfg, err := LoadFile(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: validate: %v", name, err)
		}
	}
	if checked == 0 {
		t.Fatal("no alerts.*.yaml examples found")
	}
}
