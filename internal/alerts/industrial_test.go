package alerts

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultConfig_IndustrialRulesOn(t *testing.T) {
	t.Parallel()
	c := DefaultConfig().Industrial
	for name, r := range map[string]IndustrialRule{"write": c.ModbusWrite, "diagnostic": c.ModbusDiagnostic} {
		if !r.Enabled || r.Severity != "high" || r.RealertSeconds != defaultIndustrialRealertSeconds || len(r.AllowedSources) != 0 {
			t.Fatalf("%s default = %+v", name, r)
		}
	}
}

func TestParse_IndustrialOverlay(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
industrial:
  modbus_write:
    severity: medium
    allowed_sources: ["10.0.0.10", "10.0.1.0/24"]
    realert_seconds: 120
  modbus_diagnostic:
    enabled: false
`), ".yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	w := cfg.Industrial.ModbusWrite
	if !w.Enabled || w.Severity != "medium" || w.RealertSeconds != 120 || len(w.AllowedSources) != 2 {
		t.Fatalf("modbus_write = %+v", w)
	}
	if cfg.Industrial.ModbusDiagnostic.Enabled {
		t.Fatal("modbus_diagnostic should be disabled")
	}
	if cfg.Industrial.ModbusDiagnostic.Severity != "high" {
		t.Fatal("omitted fields must keep their defaults")
	}
}

func TestParse_IndustrialOmittedKeepsDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`{"target_history_size": 30}`), ".json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, want := cfg.Industrial.ModbusWrite, DefaultConfig().Industrial.ModbusWrite
	if got.Enabled != want.Enabled || got.Severity != want.Severity ||
		got.RealertSeconds != want.RealertSeconds || len(got.AllowedSources) != 0 {
		t.Fatalf("industrial changed: %+v", cfg.Industrial)
	}
}

func TestParse_IndustrialValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, yaml, want string
	}{
		{"bad severity", "industrial:\n  modbus_write:\n    severity: critical\n", "unknown severity"},
		{"negative realert", "industrial:\n  modbus_diagnostic:\n    realert_seconds: -1\n", "realert_seconds"},
		{"bad source", "industrial:\n  modbus_write:\n    allowed_sources: [\"plc-01\"]\n", "allowed_sources"},
		{"bad cidr", "industrial:\n  modbus_write:\n    allowed_sources: [\"10.0.0.0/40\"]\n", "allowed_sources"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tt.yaml), ".yaml")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestParse_DisabledIndustrialRuleSkipsValidation(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("industrial:\n  modbus_write:\n    enabled: false\n    severity: nonsense\n"), ".yaml")
	if err != nil {
		t.Fatalf("disabled rule should not be validated: %v", err)
	}
}

func TestIndustrialRule_SourcePrefixes(t *testing.T) {
	t.Parallel()
	r := IndustrialRule{AllowedSources: []string{"10.0.0.10", "10.0.1.0/24", "2001:db8::/32", "junk"}}
	got := r.SourcePrefixes()
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.10/32"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(got) != len(want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prefixes = %v, want %v", got, want)
		}
	}
}

func TestIndustrialRules_CoverEveryField(t *testing.T) {
	t.Parallel()
	c := DefaultConfig().Industrial
	ids := map[string]bool{}
	for _, r := range c.Rules() {
		if r.Rule == nil || ids[r.ID] {
			t.Fatalf("bad or duplicate rule %q", r.ID)
		}
		ids[r.ID] = true
	}
	// Every IndustrialRule field must be reachable through Rules(), or
	// it would be neither validated nor merged from the file.
	if n := reflect.TypeOf(c).NumField(); len(ids) != n {
		t.Fatalf("Rules() lists %d rules, IndustrialConfig has %d fields", len(ids), n)
	}
	if c.S7Write.Severity != "medium" || c.S7Control.Severity != "high" || c.S7Program.Severity != "high" {
		t.Fatalf("S7 defaults = %+v %+v %+v", c.S7Write, c.S7Control, c.S7Program)
	}
}

func TestParse_S7Overlay(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("industrial:\n  s7_write:\n    enabled: false\n  s7_program:\n    allowed_sources: [\"10.0.5.0/28\"]\n"), ".yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Industrial.S7Write.Enabled || len(cfg.Industrial.S7Program.AllowedSources) != 1 || !cfg.Industrial.S7Control.Enabled {
		t.Fatalf("industrial = %+v", cfg.Industrial)
	}
}

func TestParse_IndustrialUnknownRuleRejected(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("industrial:\n  modbus_writes:\n    enabled: false\n"), ".yaml")
	if err == nil || !strings.Contains(err.Error(), `unknown rule "modbus_writes"`) {
		t.Fatalf("err = %v", err)
	}
}
