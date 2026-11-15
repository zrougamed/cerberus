package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/capture"
	"github.com/zrougamed/cerberus/internal/monitor"
)

func newCaptureServer(t *testing.T, enabled bool) http.Handler {
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
	if enabled {
		cfg := alerts.DefaultConfig().Capture
		cfg.Enabled = true
		c, err := capture.New(cfg, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Stop)
		srv.SetCapture(c)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCaptures_NowListDownloadDelete(t *testing.T) {
	h := newCaptureServer(t, true)
	rr := doJSON(h, http.MethodPost, "/api/v1/captures", assetTestToken, `{"address":"10.0.0.5","seconds":30}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("capture now: %d %s", rr.Code, rr.Body)
	}
	var c capture.Capture
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	if c.Address != "10.0.0.5" || c.Reason != "manual" || c.Bytes == 0 {
		t.Fatalf("capture = %+v", c)
	}

	rr = doJSON(h, http.MethodGet, "/api/v1/captures", "", "")
	var list capturesResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if !list.Enabled || len(list.Captures) != 1 || list.Captures[0].ID != c.ID {
		t.Fatalf("list = %+v", list)
	}

	rr = doJSON(h, http.MethodGet, "/api/v1/captures/"+c.ID, assetTestToken, "")
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/x-pcapng" ||
		!strings.Contains(rr.Header().Get("Content-Disposition"), "cerberus-"+c.ID+".pcapng") {
		t.Fatalf("download: %d %v", rr.Code, rr.Header())
	}
	if b := rr.Body.Bytes(); len(b) < 4 || b[0] != 0x0A || b[1] != 0x0D || b[2] != 0x0D || b[3] != 0x0A {
		t.Fatalf("not a pcapng file: % x", b[:min(len(b), 8)])
	}

	scrape := httptest.NewRecorder()
	h.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), "cerberus_capture_buffer_packets 0") ||
		!strings.Contains(scrape.Body.String(), "cerberus_capture_kernel_drops_total 0") {
		t.Fatal("capture metrics missing")
	}

	if rr := doJSON(h, http.MethodDelete, "/api/v1/captures/"+c.ID, assetTestToken, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body)
	}
	if rr := doJSON(h, http.MethodDelete, "/api/v1/captures/"+c.ID, assetTestToken, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rr.Code)
	}
}

func TestCaptures_AuthAndValidation(t *testing.T) {
	h := newCaptureServer(t, true)
	tests := []struct {
		name, method, path, token, body string
		status                          int
	}{
		{"download needs token", http.MethodGet, "/api/v1/captures/0123456789abcdef", "", "", http.StatusUnauthorized},
		{"capture needs token", http.MethodPost, "/api/v1/captures", "", `{"seconds":10}`, http.StatusUnauthorized},
		{"unknown download", http.MethodGet, "/api/v1/captures/0123456789abcdef", assetTestToken, "", http.StatusNotFound},
		{"traversal id", http.MethodGet, "/api/v1/captures/..%2f..%2fetc", assetTestToken, "", http.StatusNotFound},
		{"bad address", http.MethodPost, "/api/v1/captures", assetTestToken, `{"address":"plc-1","seconds":10}`, http.StatusBadRequest},
		{"zero window", http.MethodPost, "/api/v1/captures", assetTestToken, `{"seconds":0}`, http.StatusBadRequest},
		{"window past buffer", http.MethodPost, "/api/v1/captures", assetTestToken, `{"seconds":99999}`, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/v1/captures", assetTestToken, `{"seconds":5,"x":1}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rr := doJSON(h, tt.method, tt.path, tt.token, tt.body); rr.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.status, rr.Body)
			}
		})
	}
	// Whole-segment capture without an address.
	if rr := doJSON(h, http.MethodPost, "/api/v1/captures", assetTestToken, `{"seconds":5}`); rr.Code != http.StatusCreated {
		t.Fatalf("all-traffic capture: %d %s", rr.Code, rr.Body)
	}
}

func TestCaptures_Disabled(t *testing.T) {
	h := newCaptureServer(t, false)
	rr := doJSON(h, http.MethodGet, "/api/v1/captures", "", "")
	var list capturesResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if rr.Code != http.StatusOK || list.Enabled || list.Captures == nil {
		t.Fatalf("list: %d %+v", rr.Code, list)
	}
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/captures", `{"seconds":5}`},
		{http.MethodGet, "/api/v1/captures/0123456789abcdef", ""},
		{http.MethodDelete, "/api/v1/captures/0123456789abcdef", ""},
	} {
		if rr := doJSON(h, req.method, req.path, assetTestToken, req.body); rr.Code != http.StatusConflict {
			t.Fatalf("%s %s: %d", req.method, req.path, rr.Code)
		}
	}
	scrape := httptest.NewRecorder()
	h.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(scrape.Body.String(), "cerberus_capture_") {
		t.Fatal("capture metrics emitted while disabled")
	}
}
