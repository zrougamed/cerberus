package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/tidwall/buntdb"

	"github.com/zrougamed/cerberus/internal/alerts"
)

// Where the active segmentation came from.
const (
	SegmentationFromConfig = "config" // the alerts config file
	SegmentationFromSaved  = "saved"  // edited from the console or API
)

const segmentationKey = "segmentation:config"

// SegmentationState is the active segmentation and its origin.
type SegmentationState struct {
	Source string `json:"source"`
	alerts.SegmentationConfig
}

// loadSegmentation returns the saved segmentation, or the config file's
// when nothing was saved or the saved copy no longer validates.
func loadSegmentation(db *buntdb.DB, fromFile alerts.SegmentationConfig) (alerts.SegmentationConfig, string) {
	var saved alerts.SegmentationConfig
	err := db.View(func(tx *buntdb.Tx) error {
		v, err := tx.Get(segmentationKey)
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(v), &saved)
	})
	switch {
	case errors.Is(err, buntdb.ErrNotFound):
		return fromFile, SegmentationFromConfig
	case err != nil:
		log.Printf("monitor: ignoring saved segmentation: %v", err)
		return fromFile, SegmentationFromConfig
	}
	if err := saved.Validate(); err != nil {
		log.Printf("monitor: ignoring saved segmentation: %v", err)
		return fromFile, SegmentationFromConfig
	}
	return saved, SegmentationFromSaved
}

// GetSegmentation returns the active zones, conduits and zone alert rules.
func (nm *NetworkMonitor) GetSegmentation() SegmentationState {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return SegmentationState{Source: nm.segSource, SegmentationConfig: nm.segmentation.Normalize()}
}

// OnSegmentationChange registers fn to run after zones change, so the
// policy engine can follow the watch-only zones.
func (nm *NetworkMonitor) OnSegmentationChange(fn func(alerts.SegmentationConfig)) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.onSegChange = fn
}

// SetSegmentation validates, saves and applies a new segmentation. It
// takes effect for the next packet; no restart is needed.
func (nm *NetworkMonitor) SetSegmentation(cfg alerts.SegmentationConfig) error {
	cfg = cfg.Normalize()
	matcher, err := alerts.NewZoneMatcher(cfg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSegmentation, err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := nm.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(segmentationKey, string(data), nil)
		return err
	}); err != nil {
		return fmt.Errorf("save segmentation: %w", err)
	}
	nm.applySegmentation(cfg, matcher, SegmentationFromSaved)
	return nil
}

// ResetSegmentation drops the saved segmentation and goes back to the
// config file's.
func (nm *NetworkMonitor) ResetSegmentation() error {
	err := nm.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(segmentationKey)
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("delete saved segmentation: %w", err)
	}
	cfg := nm.alertConfig.Segmentation
	matcher, _ := alerts.NewZoneMatcher(cfg) // validated at startup
	nm.applySegmentation(cfg, matcher, SegmentationFromConfig)
	return nil
}

// ErrInvalidSegmentation wraps validation errors from SetSegmentation.
var ErrInvalidSegmentation = errors.New("invalid segmentation")

func (nm *NetworkMonitor) applySegmentation(cfg alerts.SegmentationConfig, matcher *alerts.ZoneMatcher, source string) {
	nm.mu.Lock()
	nm.segmentation = cfg
	nm.segSource = source
	nm.zones = matcher
	// Re-alert state and counters refer to the old zone ids.
	clear(nm.zoneLast)
	clear(nm.zoneViolations)
	for _, mac := range nm.Cache.Keys() {
		if d, ok := nm.Cache.Peek(mac); ok {
			d.Zone = ""
		}
	}
	hook := nm.onSegChange
	nm.mu.Unlock()
	if hook != nil {
		hook(cfg)
	}
}
