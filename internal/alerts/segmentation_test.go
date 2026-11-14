package alerts

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

const plantYAML = `
segmentation:
  zones:
    - id: enterprise
      level: 4
      cidrs: [10.0.0.0/16]
    - id: supervisory
      name: SCADA servers
      level: 2
      cidrs: [10.10.0.0/24]
    - id: control
      level: 1
      cidrs: [10.20.0.0/24]
      industrial: true
    - id: safety
      level: 1
      cidrs: [10.20.0.128/25]
      industrial: true
      enforce: true
  conduits:
    - {from: supervisory, to: control, ports: [502, 102]}
    - {from: enterprise, to: supervisory, ports: [443], bidirectional: true}
    - {from: control, to: safety}
  level_skip:
    severity: medium
`

func plantMatcher(t *testing.T) (*ZoneMatcher, SegmentationConfig) {
	t.Helper()
	cfg, err := Parse([]byte(plantYAML), ".yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, err := NewZoneMatcher(cfg.Segmentation)
	if err != nil || m == nil {
		t.Fatalf("matcher: %v", err)
	}
	return m, cfg.Segmentation
}

func TestSegmentation_ParseDefaults(t *testing.T) {
	t.Parallel()
	_, seg := plantMatcher(t)
	byID := map[string]Zone{}
	for _, z := range seg.Zones {
		byID[z.ID] = z
	}
	if byID["enterprise"].Name != "enterprise" || !byID["enterprise"].Enforce {
		t.Fatalf("ordinary zone defaults = %+v", byID["enterprise"])
	}
	if byID["control"].Enforce || !byID["safety"].Enforce || byID["supervisory"].Name != "SCADA servers" {
		t.Fatalf("zones = %+v", byID)
	}
	if seg.LevelSkip.Severity != "medium" || !seg.NoConduit.Enabled || seg.NoConduit.Severity != "medium" {
		t.Fatalf("rules = %+v %+v", seg.NoConduit, seg.LevelSkip)
	}
	if d := DefaultConfig().Segmentation; len(d.Zones) != 0 || d.LevelSkip.Severity != "high" {
		t.Fatalf("default = %+v", d)
	}
}

func TestZoneMatcher_LongestPrefixWins(t *testing.T) {
	t.Parallel()
	m, _ := plantMatcher(t)
	for addr, want := range map[string]string{
		"10.20.0.5":        "control",
		"10.20.0.200":      "safety",
		"10.0.3.4":         "enterprise",
		"::ffff:10.10.0.9": "supervisory",
		"192.168.1.1":      "",
	} {
		z := m.Zone(netip.MustParseAddr(addr))
		got := ""
		if z != nil {
			got = z.ID
		}
		if got != want {
			t.Errorf("Zone(%s) = %q, want %q", addr, got, want)
		}
	}
	if m.Zone(netip.Addr{}) != nil {
		t.Error("invalid address matched")
	}
	var nilMatcher *ZoneMatcher
	if nilMatcher.Zone(netip.MustParseAddr("10.0.0.1")) != nil || nilMatcher.Zones() != nil || nilMatcher.Conduits() != nil {
		t.Error("nil matcher returned data")
	}
	if len(m.Zones()) != 4 || len(m.Conduits()) != 3 {
		t.Error("zones or conduits missing")
	}
}

func TestZoneMatcher_Allowed(t *testing.T) {
	t.Parallel()
	m, _ := plantMatcher(t)
	tests := []struct {
		name         string
		from, to     string
		sport, dport uint16
		syn, want    bool
	}{
		{"scada polls modbus", "supervisory", "control", 50000, 502, true, true},
		{"plc replies", "control", "supervisory", 502, 50000, false, true},
		{"plc opens a connection back", "control", "supervisory", 50001, 502, true, false},
		{"plc syn from service port", "control", "supervisory", 502, 50000, true, false},
		{"scada on unlisted port", "supervisory", "control", 50000, 22, true, false},
		{"bidirectional either way", "supervisory", "enterprise", 50000, 443, true, true},
		{"any-port conduit", "control", "safety", 40000, 9999, true, true},
		{"any-port reply", "safety", "control", 9999, 40000, false, true},
		{"any-port reverse open", "safety", "control", 40000, 9999, true, false},
		{"no conduit", "enterprise", "control", 50000, 502, true, false},
	}
	for _, tt := range tests {
		if got := m.Allowed(tt.from, tt.to, tt.sport, tt.dport, tt.syn); got != tt.want {
			t.Errorf("%s: Allowed = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSegmentation_WatchOnlyPrefixes(t *testing.T) {
	t.Parallel()
	_, seg := plantMatcher(t)
	w := seg.WatchOnlyPrefixes()
	if len(w) != 1 || len(w["control"]) != 1 || w["control"][0] != netip.MustParsePrefix("10.20.0.0/24") {
		t.Fatalf("watch-only = %v", w)
	}
}

func TestSegmentation_Validation(t *testing.T) {
	t.Parallel()
	zone := "segmentation:\n  zones:\n    - {id: a, level: 1, cidrs: [10.0.0.0/8]}\n"
	tests := map[string]string{
		"segmentation:\n  zones:\n    - {id: 'bad id', level: 1, cidrs: [10.0.0.0/8]}\n":                          "id",
		zone + "    - {id: a, level: 2, cidrs: [10.1.0.0/16]}\n":                                                  "duplicate",
		"segmentation:\n  zones:\n    - {id: a, level: 6, cidrs: [10.0.0.0/8]}\n":                                 "level",
		"segmentation:\n  zones:\n    - {id: a, level: 1}\n":                                                      "cidrs must not be empty",
		"segmentation:\n  zones:\n    - {id: a, level: 1, cidrs: [nope]}\n":                                       "bad address",
		zone + "  conduits:\n    - {from: a, to: b}\n":                                                            "must name zones",
		zone + "  conduits:\n    - {from: a, to: a}\n":                                                            "same zone",
		zone + "    - {id: b, level: 2, cidrs: [10.0.0.0/16]}\n  conduits:\n    - {from: a, to: b, ports: [0]}\n": "out of range",
		"segmentation:\n  no_conduit:\n    severity: loud\n":                                                      "unknown severity",
		"segmentation:\n  level_skip:\n    realert_seconds: -1\n":                                                 "realert_seconds",
	}
	for yaml, want := range tests {
		if _, err := Parse([]byte(yaml), ".yaml"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", yaml, err, want)
		}
	}
	if _, err := Parse([]byte("segmentation:\n  no_conduit:\n    enabled: false\n    severity: loud\n"), ".yaml"); err != nil {
		t.Errorf("disabled rule validated: %v", err)
	}
	var many strings.Builder
	many.WriteString("segmentation:\n  zones:\n    - id: big\n      level: 1\n      cidrs:\n")
	for i := range maxZonePrefixes + 1 {
		many.WriteString("        - 10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + "\n")
	}
	if _, err := Parse([]byte(many.String()), ".yaml"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("prefix cap: %v", err)
	}
	if m, err := NewZoneMatcher(DefaultConfig().Segmentation); m != nil || err != nil {
		t.Errorf("empty config matcher = %v, %v", m, err)
	}
	if _, err := NewZoneMatcher(SegmentationConfig{Zones: []Zone{{ID: "x", Level: 9, CIDRs: []string{"10.0.0.0/8"}}}}); err == nil {
		t.Error("invalid config compiled")
	}
}
