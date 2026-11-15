package alerts

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse_WatchlistDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(`
watchlists:
  - id: tor-exits
    cidrs: ["203.0.113.0/24", "2001:db8::/32", "198.51.100.7"]
  - id: off
    enabled: false
`), ".yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Watchlists) != 2 {
		t.Fatalf("expected 2 watchlists, got %d", len(cfg.Watchlists))
	}
	w := cfg.Watchlists[0]
	if !w.Enabled || w.Direction != DirectionAny || w.Severity != "high" || w.RealertSeconds != defaultRealertSeconds {
		t.Fatalf("defaults not applied: %+v", w)
	}
	if cfg.Watchlists[1].Enabled {
		t.Fatal("explicit enabled: false must be kept")
	}
	// A disabled list needs no cidrs.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestParse_WatchlistsOmittedKeepsNone(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("target_history_size: 64\n"), ".yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Watchlists) != 0 {
		t.Fatalf("expected no watchlists, got %d", len(cfg.Watchlists))
	}
}

func TestValidateWatchlists_Errors(t *testing.T) {
	t.Parallel()
	ok := Watchlist{ID: "x", Enabled: true, CIDRs: []string{"10.0.0.0/8"}, Direction: DirectionAny, Severity: "low"}
	with := func(f func(*Watchlist)) []Watchlist {
		w := ok
		f(&w)
		return []Watchlist{w}
	}
	tests := []struct {
		name  string
		lists []Watchlist
		want  string
	}{
		{"empty id", with(func(w *Watchlist) { w.ID = "" }), "id"},
		{"bad id chars", with(func(w *Watchlist) { w.ID = "a b" }), "id"},
		{"duplicate id", []Watchlist{ok, ok}, "duplicate"},
		{"no cidrs", with(func(w *Watchlist) { w.CIDRs = nil }), "cidrs"},
		{"bad cidr", with(func(w *Watchlist) { w.CIDRs = []string{"10.0.0.0/33"} }), "not a valid address range"},
		{"bad address", with(func(w *Watchlist) { w.CIDRs = []string{"not-an-ip"} }), "not a valid IP address"},
		{"bad direction", with(func(w *Watchlist) { w.Direction = "both" }), "direction"},
		{"bad severity", with(func(w *Watchlist) { w.Severity = "critical" }), "severity"},
		{"negative realert", with(func(w *Watchlist) { w.RealertSeconds = -1 }), "realert"},
		{"too many prefixes", with(func(w *Watchlist) {
			w.CIDRs = make([]string, maxWatchlistPrefixes+1)
			for i := range w.CIDRs {
				w.CIDRs[i] = "10.0.0.1"
			}
		}), "exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateWatchlists(tc.lists)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestWatchlistMatcher_Match(t *testing.T) {
	t.Parallel()
	m, err := NewWatchlistMatcher([]Watchlist{
		{ID: "bad-net", Enabled: true, CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Direction: DirectionAny, Severity: "high"},
		{ID: "c2-dst", Enabled: true, CIDRs: []string{"198.51.100.7"}, Direction: DirectionDst, Severity: "medium"},
		{ID: "scanner-src", Enabled: true, CIDRs: []string{"192.0.2.0/28"}, Direction: DirectionSrc, Severity: "low"},
		{ID: "disabled", Enabled: false, CIDRs: []string{"0.0.0.0/0"}},
	})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	a := netip.MustParseAddr
	tests := []struct {
		name     string
		src, dst netip.Addr
		want     map[string]string // list id -> remote
	}{
		{"no match", a("10.0.0.5"), a("10.0.0.1"), nil},
		{"any matches dst", a("10.0.0.5"), a("203.0.113.9"), map[string]string{"bad-net": "203.0.113.9"}},
		{"any matches src", a("203.0.113.200"), a("10.0.0.5"), map[string]string{"bad-net": "203.0.113.200"}},
		{"ipv6 prefix", a("fd00::1"), a("2001:db8:1::5"), map[string]string{"bad-net": "2001:db8:1::5"}},
		{"ipv4-mapped ipv6 unmapped", a("10.0.0.5"), a("::ffff:203.0.113.1"), map[string]string{"bad-net": "203.0.113.1"}},
		{"dst-only list ignores src", a("198.51.100.7"), a("10.0.0.5"), nil},
		{"dst-only list matches dst", a("10.0.0.5"), a("198.51.100.7"), map[string]string{"c2-dst": "198.51.100.7"}},
		{"src-only list ignores dst", a("10.0.0.5"), a("192.0.2.3"), nil},
		{"src-only list matches src", a("192.0.2.15"), a("10.0.0.5"), map[string]string{"scanner-src": "192.0.2.15"}},
		{"outside /28", a("192.0.2.16"), a("10.0.0.5"), nil},
		{"several lists at once", a("192.0.2.1"), a("198.51.100.7"), map[string]string{"c2-dst": "198.51.100.7", "scanner-src": "192.0.2.1"}},
		{"invalid addresses", netip.Addr{}, netip.Addr{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hits := m.Match(tc.src, tc.dst)
			got := make(map[string]string, len(hits))
			for _, h := range hits {
				got[h.List.ID] = h.Remote.String()
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for id, remote := range tc.want {
				if got[id] != remote {
					t.Fatalf("list %s: got %q, want %q (all hits %v)", id, got[id], remote, got)
				}
			}
		})
	}
}

func TestWatchlistMatcher_Empty(t *testing.T) {
	t.Parallel()
	var nilMatcher *WatchlistMatcher
	if !nilMatcher.Empty() || nilMatcher.Match(netip.MustParseAddr("10.0.0.1"), netip.Addr{}) != nil {
		t.Fatal("nil matcher must be empty and match nothing")
	}
	m, err := NewWatchlistMatcher([]Watchlist{{ID: "off", Enabled: false}})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	if !m.Empty() {
		t.Fatal("matcher with only disabled lists must be empty")
	}
	if _, err := NewWatchlistMatcher([]Watchlist{{ID: "bad id"}}); err == nil {
		t.Fatal("expected validation error")
	}
}

// Every shipped example must load, so a schema change cannot silently break
// the files users copy.
func TestShippedConfigsLoad(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("../../configs/alerts.*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no example configs found: %v", err)
	}
	for _, f := range files {
		cfg, err := LoadFile(f)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if filepath.Base(f) == "alerts.watchlists.yaml" && len(cfg.Watchlists) != 3 {
			t.Errorf("alerts.watchlists.yaml: expected 3 watchlists, got %d", len(cfg.Watchlists))
		}
	}
}
