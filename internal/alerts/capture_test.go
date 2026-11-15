package alerts

import (
	"strings"
	"testing"
)

func TestCapture_DefaultsAndOverlay(t *testing.T) {
	t.Parallel()
	d := DefaultConfig().Capture
	if d.Enabled || d.Snaplen != 1518 || d.BufferSeconds != 120 || d.OnAlert.MinSeverity != "high" || d.OnAlert.BeforeSeconds != 30 || d.MaxFiles != 50 {
		t.Fatalf("defaults = %+v", d)
	}
	cfg, err := Parse([]byte(`
capture:
  enabled: true
  interfaces: [eth1]
  snaplen: 256
  buffer_seconds: 60
  buffer_mb: 16
  max_files: 5
  max_total_mb: 50
  dir: /var/lib/cerberus/pcap
  on_alert:
    min_severity: medium
    before_seconds: 20
    after_seconds: 5
    min_interval_seconds: 60
`), ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Capture
	if !c.Enabled || c.Interfaces[0] != "eth1" || c.Snaplen != 256 || c.BufferSeconds != 60 || c.BufferMB != 16 ||
		c.MaxFiles != 5 || c.MaxTotalMB != 50 || c.Dir != "/var/lib/cerberus/pcap" {
		t.Fatalf("capture = %+v", c)
	}
	if o := c.OnAlert; !o.Enabled || o.MinSeverity != "medium" || o.BeforeSeconds != 20 || o.AfterSeconds != 5 || o.MinIntervalSeconds != 60 {
		t.Fatalf("on_alert = %+v", o)
	}
}

func TestCapture_Validation(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]string{
		"snaplen: 10":                          "snaplen",
		"buffer_seconds: 0":                    "buffer_seconds",
		"buffer_mb: 5000":                      "buffer_mb",
		"max_files: 0":                         "max_files",
		"max_total_mb: 0":                      "max_total_mb",
		"on_alert: {min_severity: urgent}":     "min_severity",
		"on_alert: {before_seconds: 500}":      "before_seconds",
		"on_alert: {after_seconds: 900}":       "after_seconds",
		"on_alert: {min_interval_seconds: -1}": "min_interval_seconds",
	} {
		_, err := Parse([]byte("capture:\n  enabled: true\n  "+body+"\n"), ".yaml")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
	if _, err := Parse([]byte("capture:\n  enabled: false\n  snaplen: 1\n"), ".yaml"); err != nil {
		t.Errorf("disabled capture validated: %v", err)
	}
	if _, err := Parse([]byte("capture:\n  enabled: true\n  on_alert: {enabled: false, min_severity: x}\n"), ".yaml"); err != nil {
		t.Errorf("disabled on_alert validated: %v", err)
	}
}
