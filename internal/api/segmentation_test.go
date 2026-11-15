package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/monitor"
)

func newSegmentationServer(t *testing.T) http.Handler {
	t.Helper()
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	srv := NewServer(mon)
	if err := srv.SetAPIToken(assetTestToken); err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const plantBody = `{
  "zones": [
    {"id": "office", "name": "Office LAN", "level": 4, "cidrs": ["10.0.0.0/16"], "enforce": true},
    {"id": "line1", "name": "Line 1", "level": 1, "cidrs": ["10.20.0.0/24"], "industrial": true}
  ],
  "conduits": [{"from": "office", "to": "line1", "ports": [443]}],
  "no_conduit": {"enabled": true, "severity": "medium", "realert_seconds": 600},
  "level_skip": {"enabled": true, "severity": "high", "realert_seconds": 600}
}`

func TestSegmentationAPI_PutGetReset(t *testing.T) {
	h := newSegmentationServer(t)
	var got monitor.SegmentationState
	rr := doJSON(h, http.MethodGet, "/api/v1/segmentation", "", "")
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.Source != "config" || len(got.Zones) != 0 || got.LevelSkip.Severity != "high" {
		t.Fatalf("initial = %+v", got)
	}

	rr = doJSON(h, http.MethodPut, "/api/v1/segmentation", assetTestToken, plantBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rr.Code, rr.Body)
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.Source != "saved" || len(got.Zones) != 2 || got.Zones[1].Name != "Line 1" || got.NoConduit.RealertSeconds != 600 {
		t.Fatalf("after put = %+v", got)
	}
	rr = doJSON(h, http.MethodGet, "/api/v1/zones", "", "")
	if !strings.Contains(rr.Body.String(), `"id":"line1"`) {
		t.Fatalf("zones summary not updated: %s", rr.Body)
	}

	rr = doJSON(h, http.MethodDelete, "/api/v1/segmentation", assetTestToken, "")
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusOK || got.Source != "config" || len(got.Zones) != 0 {
		t.Fatalf("reset: %d %+v", rr.Code, got)
	}
}

func TestSegmentationAPI_Errors(t *testing.T) {
	h := newSegmentationServer(t)
	tests := []struct {
		name, method, token, body, want string
		status                          int
	}{
		{"no token", http.MethodPut, "", plantBody, "", http.StatusUnauthorized},
		{"reset without token", http.MethodDelete, "", "", "", http.StatusUnauthorized},
		{"bad level", http.MethodPut, assetTestToken, `{"zones":[{"id":"a","level":7,"cidrs":["10.0.0.0/8"]}]}`, "level must be between 0 and 5", http.StatusBadRequest},
		{"conduit to unknown zone", http.MethodPut, assetTestToken, `{"zones":[{"id":"a","level":1,"cidrs":["10.0.0.0/8"]}],"conduits":[{"from":"a","to":"b"}]}`, "must name zones", http.StatusBadRequest},
		{"bad cidr", http.MethodPut, assetTestToken, `{"zones":[{"id":"a","level":1,"cidrs":["10.0.0.0/33"]}]}`, "not a valid address range", http.StatusBadRequest},
		{"unknown field", http.MethodPut, assetTestToken, `{"zonez":[]}`, "unknown field", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := doJSON(h, tt.method, "/api/v1/segmentation", tt.token, tt.body)
			if rr.Code != tt.status || !strings.Contains(rr.Body.String(), tt.want) {
				t.Fatalf("status = %d body = %s, want %d %q", rr.Code, rr.Body, tt.status, tt.want)
			}
		})
	}
}
