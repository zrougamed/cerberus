package policy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func watchOnlyOptions() Options {
	return Options{WatchOnly: map[string][]netip.Prefix{
		"control": {netip.MustParsePrefix("10.20.0.0/24")},
		"safety":  {netip.MustParsePrefix("10.21.0.0/24")},
	}}
}

func TestAdd_WatchOnlyZoneNeedsForce(t *testing.T) {
	t.Parallel()
	e, _ := boundEngine(t, watchOnlyOptions())
	tests := []struct {
		name string
		in   RuleInput
		ok   bool
	}{
		{"drop inside zone", RuleInput{Action: ActionDrop, CIDR: "10.20.0.50"}, false},
		{"drop covering zone", RuleInput{Action: ActionDrop, CIDR: "10.0.0.0/8"}, false},
		{"drop outside zone", RuleInput{Action: ActionDrop, CIDR: "10.30.0.0/24"}, true},
		{"count inside zone", RuleInput{Action: ActionLog, CIDR: "10.20.0.51"}, true},
		{"forced drop inside zone", RuleInput{Action: ActionDrop, CIDR: "10.20.0.52", Force: true}, true},
		{"mac rule unaffected", RuleInput{Action: ActionDrop, MAC: "02:00:00:00:00:99"}, true},
	}
	for _, tt := range tests {
		_, err := e.Add(tt.in, "t")
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.name, err)
		}
		if err != nil && (!errors.Is(err, ErrProtected) || !strings.Contains(err.Error(), "watch-only zone")) {
			t.Errorf("%s: wrong error %v", tt.name, err)
		}
	}
	if _, err := e.Add(RuleInput{Action: ActionDrop, CIDR: "10.0.0.0/8"}, "t"); err == nil ||
		!strings.Contains(err.Error(), "control (10.20.0.0/24)") {
		t.Errorf("error should name the first zone in order: %v", err)
	}
}

func TestAddFilter_WatchOnlyZoneNeedsForce(t *testing.T) {
	t.Parallel()
	e, _ := boundEngine(t, watchOnlyOptions())
	tests := []struct {
		name  string
		match FilterMatch
		verd  string
		force bool
		ok    bool
	}{
		{"block dst in zone", FilterMatch{Protocol: "tcp", Dst: "10.20.0.50", DstPort: "502"}, "drop", false, false},
		{"block src in zone", FilterMatch{Src: "10.21.0.0/25"}, "drop", false, false},
		{"block outside zones", FilterMatch{Src: "192.0.2.0/24"}, "drop", false, true},
		{"count in zone", FilterMatch{Dst: "10.20.0.50"}, "continue", false, true},
		{"forced block in zone", FilterMatch{Dst: "10.20.0.50"}, "drop", true, true},
		{"negated side covering both zones", FilterMatch{Src: "192.0.2.1", Dst: "10.0.0.0/8", DstNot: true}, "drop", false, true},
		{"negated side leaving a zone exposed", FilterMatch{Src: "192.0.2.1", Dst: "10.20.0.0/16", DstNot: true}, "drop", false, false},
		{"negated narrower than zone", FilterMatch{Src: "192.0.2.1", Dst: "10.20.0.0/25", DstNot: true}, "drop", false, false},
	}
	for _, tt := range tests {
		_, err := e.AddFilter(FilterInput{Match: tt.match, Verdict: Verdict(tt.verd), Force: tt.force}, "t")
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "watch-only zone") {
			t.Errorf("%s: wrong error %v", tt.name, err)
		}
	}
}

func TestWatchOnlyHit_InvalidPrefix(t *testing.T) {
	t.Parallel()
	e, _ := boundEngine(t, watchOnlyOptions())
	if z := e.watchOnlyHit(netip.Prefix{}); z != "" {
		t.Fatalf("invalid prefix hit %q", z)
	}
}
