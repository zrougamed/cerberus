package monitor

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/tidwall/buntdb"

	"github.com/zrougamed/cerberus/internal/alerts"
)

func editedSegmentation() alerts.SegmentationConfig {
	s := alerts.DefaultConfig().Segmentation
	s.Zones = []alerts.Zone{
		{ID: " office ", Level: 4, CIDRs: []string{"10.0.0.0/16"}, Enforce: true},
		{ID: "line1", Name: "Line 1", Level: 1, CIDRs: []string{"10.20.0.0/24"}, Industrial: true},
	}
	s.Conduits = []alerts.Conduit{{From: "office", To: "line1", Ports: []int{443}}}
	return s
}

func TestSetSegmentation_AppliesLiveAndPersists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	cfg := alerts.DefaultConfig()
	nm, err := NewNetworkMonitorWithAlerts(10, dbPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := nm.GetSegmentation(); s.Source != SegmentationFromConfig || len(s.Zones) != 0 {
		t.Fatalf("initial = %+v", s)
	}
	var hooked []alerts.Zone
	nm.OnSegmentationChange(func(c alerts.SegmentationConfig) { hooked = c.Zones })

	if err := nm.SetSegmentation(editedSegmentation()); err != nil {
		t.Fatal(err)
	}
	s := nm.GetSegmentation()
	if s.Source != SegmentationFromSaved || s.Zones[0].ID != "office" || s.Zones[0].Name != "office" || len(hooked) != 2 {
		t.Fatalf("after set = %+v hooked = %+v", s, hooked)
	}
	// Live: office -> line1 on 502 has no conduit and skips levels.
	nm.TrackEvent(tcpEvent(1, "10.0.3.3", "10.20.0.50", 50000, 502, 0x02))
	if got := zoneAlerts(nm); len(got) != 1 || got[0].Rule != alerts.RuleZoneLevelSkip {
		t.Fatalf("alerts = %+v", got)
	}
	_ = nm.Close()

	again, err := NewNetworkMonitorWithAlerts(10, dbPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if s := again.GetSegmentation(); s.Source != SegmentationFromSaved || len(s.Zones) != 2 || len(s.Conduits) != 1 {
		t.Fatalf("after restart = %+v", s)
	}
	if err := again.ResetSegmentation(); err != nil {
		t.Fatal(err)
	}
	if s := again.GetSegmentation(); s.Source != SegmentationFromConfig || len(s.Zones) != 0 {
		t.Fatalf("after reset = %+v", s)
	}
	if err := again.ResetSegmentation(); err != nil {
		t.Fatalf("second reset: %v", err)
	}
}

func TestSetSegmentation_RejectsInvalid(t *testing.T) {
	nm := zoneMonitor(t, nil)
	before := nm.GetSegmentation()
	bad := editedSegmentation()
	bad.Conduits = []alerts.Conduit{{From: "office", To: "nowhere"}}
	if err := nm.SetSegmentation(bad); !errors.Is(err, ErrInvalidSegmentation) {
		t.Fatalf("err = %v", err)
	}
	if after := nm.GetSegmentation(); after.Source != before.Source || len(after.Zones) != len(before.Zones) {
		t.Fatal("invalid segmentation was applied")
	}
}

func TestLoadSegmentation_IgnoresBadSavedCopy(t *testing.T) {
	file := alerts.DefaultConfig().Segmentation
	for name, stored := range map[string]string{
		"corrupt": "{not json",
		"invalid": `{"zones":[{"id":"x","level":9,"cidrs":["10.0.0.0/8"]}]}`,
	} {
		db, err := buntdb.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		_ = db.Update(func(tx *buntdb.Tx) error {
			_, _, err := tx.Set(segmentationKey, stored, nil)
			return err
		})
		if _, src := loadSegmentation(db, file); src != SegmentationFromConfig {
			t.Errorf("%s: source = %s", name, src)
		}
		_ = db.Close()
	}
}
