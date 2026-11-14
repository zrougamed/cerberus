package monitor

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func newWatchlistMonitor(t *testing.T, lists ...alerts.Watchlist) *NetworkMonitor {
	t.Helper()
	cfg := alerts.DefaultConfig()
	cfg.Watchlists = lists
	nm, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	return nm
}

func watchlist(id string, realert int, cidrs ...string) alerts.Watchlist {
	return alerts.Watchlist{
		ID: id, Enabled: true, CIDRs: cidrs, Direction: alerts.DirectionAny,
		Severity: "high", RealertSeconds: realert,
	}
}

func TestCheckWatchlists_CountsEveryHitAndRateLimitsAlerts(t *testing.T) {
	nm := newWatchlistMonitor(t, watchlist("bad", 600, "203.0.113.0/24"))
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.5"}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	nm.checkWatchlists(device, "10.0.0.5", "203.0.113.9", t0)
	nm.checkWatchlists(device, "10.0.0.5", "203.0.113.9", t0.Add(time.Minute))  // inside window
	nm.checkWatchlists(device, "10.0.0.5", "203.0.113.10", t0.Add(time.Minute)) // other remote
	nm.checkWatchlists(device, "10.0.0.5", "10.0.0.1", t0.Add(time.Minute))     // no match
	nm.checkWatchlists(device, "10.0.0.5", "203.0.113.9", t0.Add(11*time.Minute))

	if got := nm.GetWatchlistHits()["bad"]; got != 4 {
		t.Fatalf("hits: got %d, want 4", got)
	}
	if len(nm.alerts) != 3 {
		t.Fatalf("alerts: got %d, want 3 (first, other remote, after window): %+v", len(nm.alerts), nm.alerts)
	}
	a := nm.alerts[0]
	if a.Rule != "watchlist:bad" || a.Severity != "high" || a.DeviceMAC != device.MAC {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if want := "traffic with a watchlisted address (203.0.113.9, list bad)"; a.Message != want {
		t.Fatalf("message: got %q, want %q", a.Message, want)
	}
}

func TestCheckWatchlists_ZeroRealertAlertsEveryTime(t *testing.T) {
	nm := newWatchlistMonitor(t, watchlist("noisy", 0, "198.51.100.7"))
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:02"}
	now := time.Now()
	for range 3 {
		nm.checkWatchlists(device, "198.51.100.7", "10.0.0.2", now)
	}
	if len(nm.alerts) != 3 {
		t.Fatalf("alerts: got %d, want 3", len(nm.alerts))
	}
}

func TestCheckWatchlists_PrunesStateAtCap(t *testing.T) {
	nm := newWatchlistMonitor(t, watchlist("bad", 60, "203.0.113.0/24"))
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:03"}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range maxWatchlistAlertKeys {
		nm.watchlistLast[fmt.Sprintf("stale-%d", i)] = old
	}
	nm.checkWatchlists(device, "10.0.0.5", "203.0.113.1", old.Add(time.Hour))
	if len(nm.watchlistLast) != 1 {
		t.Fatalf("expected stale keys pruned, %d left", len(nm.watchlistLast))
	}
}

func TestGetWatchlistHits_ListsEnabledListsFromStart(t *testing.T) {
	off := watchlist("off", 0, "192.0.2.1")
	off.Enabled = false
	nm := newWatchlistMonitor(t, watchlist("on", 0, "192.0.2.2"), off)
	hits := nm.GetWatchlistHits()
	if v, ok := hits["on"]; !ok || v != 0 {
		t.Fatalf("enabled list should be reported with 0 hits: %v", hits)
	}
	if _, ok := hits["off"]; ok {
		t.Fatalf("disabled list must not be reported: %v", hits)
	}
}

func TestTrackEvent_WatchlistEndToEnd(t *testing.T) {
	nm := newWatchlistMonitor(t, watchlist("bad", 600, "203.0.113.0/24"))
	ip4 := func(a, b, c, d byte) uint32 { return binary.LittleEndian.Uint32([]byte{a, b, c, d}) }

	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_TCP,
		SrcMac:    [6]byte{0x02, 0, 0, 0, 0, 0x10},
		SrcIP:     ip4(10, 0, 0, 5),
		DstIP:     ip4(203, 0, 113, 9),
		SrcPort:   40000,
		DstPort:   443,
		Protocol:  6,
	}
	nm.TrackEvent(evt)

	arp := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ARP,
		SrcMac:    [6]byte{0x02, 0, 0, 0, 0, 0x11},
		SrcIP:     ip4(203, 0, 113, 50),
		DstIP:     ip4(10, 0, 0, 1),
		ArpOp:     1,
	}
	nm.TrackEvent(arp) // ARP is not matched against watchlists

	if got := nm.GetWatchlistHits()["bad"]; got != 1 {
		t.Fatalf("hits: got %d, want 1", got)
	}
	found := false
	for _, a := range nm.GetAlerts() {
		if a.Rule == "watchlist:bad" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a watchlist:bad alert, got %+v", nm.GetAlerts())
	}
}
