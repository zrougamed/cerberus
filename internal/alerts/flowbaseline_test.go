package alerts

import (
	"strings"
	"testing"
)

func TestFlowBaseline_DefaultsAndOverlay(t *testing.T) {
	t.Parallel()
	d := DefaultConfig().FlowBaseline
	if !d.Enabled || d.LearningHours != 168 || d.Severity != "medium" || d.MaxFlows != 10000 {
		t.Fatalf("defaults = %+v", d)
	}
	cfg, err := Parse([]byte("flow_baseline:\n  learning_hours: 24\n  severity: high\n  max_flows: 500\n"), ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.FlowBaseline; !got.Enabled || got.LearningHours != 24 || got.Severity != "high" || got.MaxFlows != 500 {
		t.Fatalf("overlay = %+v", got)
	}
	cfg, err = Parse([]byte("flow_baseline:\n  enabled: false\n  learning_hours: 0\n"), ".yaml")
	if err != nil || cfg.FlowBaseline.Enabled {
		t.Fatalf("disabled baseline: %+v err=%v", cfg.FlowBaseline, err)
	}
}

func TestFlowBaseline_Validation(t *testing.T) {
	t.Parallel()
	for yaml, want := range map[string]string{
		"flow_baseline:\n  learning_hours: 0\n":  "learning_hours",
		"flow_baseline:\n  severity: urgent\n":   "unknown severity",
		"flow_baseline:\n  max_flows: 0\n":       "max_flows",
		"flow_baseline:\n  max_flows: 1000000\n": "max_flows",
	} {
		if _, err := Parse([]byte(yaml), ".yaml"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", yaml, err, want)
		}
	}
}
