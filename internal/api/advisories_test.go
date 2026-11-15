package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/advisories"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

func writeTestBundle(t *testing.T, generated time.Time) string {
	t.Helper()
	b := advisories.Bundle{Format: advisories.BundleFormat, GeneratedAt: generated, Source: "test feed", Advisories: []advisories.Advisory{
		{ID: "ICSA-T-1", Title: "Modicon M241", Severity: "high", Score: 8.8, URL: "https://www.cisa.gov/x",
			Products: []advisories.Product{{Vendor: "Schneider Electric", Name: "Modicon Controller M241", Version: "<5.2.11.18"}}},
		{ID: "ICSA-T-2", Title: "All Modicon", Severity: "critical", Score: 9.8,
			Products: []advisories.Product{{Vendor: "Schneider Electric", Name: "Modicon Controller M241"}}},
	}}
	p := filepath.Join(t.TempDir(), "advisories.json")
	data, _ := json.Marshal(b)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newAdvisoryServer has one PLC that reports Schneider Electric / M241 /
// v5.2.10.0 over Modbus Read Device Identification.
func newAdvisoryServer(t *testing.T, bundle string) (*Server, http.Handler) {
	t.Helper()
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	vendor, model, fw := "Schneider Electric", "M241", "v5.2.10.0"
	pdu := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, byte(len(vendor))}
	pdu = append(pdu, vendor...)
	pdu = append(pdu, 0x02, byte(len(fw)))
	pdu = append(pdu, fw...)
	pdu = append(pdu, 0x05, byte(len(model)))
	pdu = append(pdu, model...)
	mon.TrackEvent(modbusTCPEvent(5, 0x0500000A, 0x0900000A, 502, 50000, pdu...))

	srv := NewServer(mon)
	if err := srv.SetAPIToken(assetTestToken); err != nil {
		t.Fatal(err)
	}
	if bundle != "" {
		if err := srv.LoadAdvisories(bundle); err != nil {
			t.Fatal(err)
		}
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return srv, h
}

func TestAdvisories_StatusMatchesAndCounts(t *testing.T) {
	_, h := newAdvisoryServer(t, writeTestBundle(t, time.Now().Add(-48*time.Hour)))
	var st advisoryStatus
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/advisories", "", "").Body.Bytes(), &st)
	if !st.Loaded || st.Advisories != 2 || st.AgeDays != 2 || st.Stale || st.Source != "test feed" {
		t.Fatalf("status = %+v", st)
	}

	rr := doJSON(h, http.MethodGet, "/api/v1/assets/02:00:00:00:00:05/advisories", "", "")
	var matches []advisories.Match
	_ = json.Unmarshal(rr.Body.Bytes(), &matches)
	if len(matches) != 2 || matches[0].ID != "ICSA-T-2" || matches[1].Confidence != advisories.MatchVersion {
		t.Fatalf("matches = %+v", matches)
	}

	assets := getAssets(t, h, "")
	var plc assetEntry
	for _, a := range assets {
		if a.MAC == "02:00:00:00:00:05" {
			plc = a
		}
	}
	if plc.Advisories != 2 || plc.AdvisorySeverity != "critical" {
		t.Fatalf("asset = %+v", plc)
	}
	rr = doJSON(h, http.MethodGet, "/api/v1/assets?format=csv", "", "")
	rows, _ := csv.NewReader(rr.Body).ReadAll()
	if rows[0][13] != "advisories" || rows[1][13] != "2" || rows[1][14] != "critical" {
		t.Fatalf("csv = %v", rows)
	}
}

func TestAdvisories_StaleAndErrors(t *testing.T) {
	srv, h := newAdvisoryServer(t, writeTestBundle(t, time.Now().Add(-200*24*time.Hour)))
	var st advisoryStatus
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/advisories", "", "").Body.Bytes(), &st)
	if !st.Stale {
		t.Fatalf("old bundle not stale: %+v", st)
	}
	for _, tt := range []struct {
		path   string
		status int
	}{
		{"/api/v1/assets/not-a-mac/advisories", http.StatusBadRequest},
		{"/api/v1/assets/02:00:00:00:00:77/advisories", http.StatusNotFound},
	} {
		if rr := doJSON(h, http.MethodGet, tt.path, "", ""); rr.Code != tt.status {
			t.Fatalf("%s: %d", tt.path, rr.Code)
		}
	}
	// A device without a reported identity has no matches.
	if rr := doJSON(h, http.MethodGet, "/api/v1/assets/02:00:00:00:00:05/advisories", "", ""); !strings.HasPrefix(rr.Body.String(), "[{") {
		t.Fatalf("plc matches = %s", rr.Body)
	}

	// Reload: auth, a broken file keeps an error in the status.
	if rr := doJSON(h, http.MethodPost, "/api/v1/advisories/reload", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("reload without token: %d", rr.Code)
	}
	good := writeTestBundle(t, time.Now())
	if err := srv.LoadAdvisories(good); err != nil {
		t.Fatal(err)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/advisories/reload", assetTestToken, ""); rr.Code != http.StatusOK {
		t.Fatalf("reload: %d %s", rr.Code, rr.Body)
	}
	_ = os.WriteFile(good, []byte("{"), 0o600)
	if rr := doJSON(h, http.MethodPost, "/api/v1/advisories/reload", assetTestToken, ""); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("broken reload: %d", rr.Code)
	}
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/advisories", "", "").Body.Bytes(), &st)
	if st.Loaded || st.Error == "" {
		t.Fatalf("status after failed reload = %+v", st)
	}
}

func TestAdvisories_NotConfigured(t *testing.T) {
	_, h := newAdvisoryServer(t, "")
	var st advisoryStatus
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/advisories", "", "").Body.Bytes(), &st)
	if st.Loaded || st.Path != "" {
		t.Fatalf("status = %+v", st)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/advisories/reload", assetTestToken, ""); rr.Code != http.StatusConflict {
		t.Fatalf("reload without a path: %d", rr.Code)
	}
	if rr := doJSON(h, http.MethodGet, "/api/v1/assets/02:00:00:00:00:05/advisories", "", ""); rr.Body.String() != "[]\n" && rr.Body.String() != "[]" {
		t.Fatalf("matches without bundle = %q", rr.Body)
	}
}

func TestAssetForMatching(t *testing.T) {
	t.Parallel()
	if _, ok := assetForMatching(&models.DeviceInfo{}); ok {
		t.Fatal("device without asset matched")
	}
	a, ok := assetForMatching(&models.DeviceInfo{Vendor: "Rockwell Automation", Asset: &models.AssetInfo{Vendor: "CIP vendor 1", Model: "1769-L33ER", Firmware: "33.011"}})
	if !ok || a.Vendor != "Rockwell Automation" || a.Model != "1769-L33ER" || a.Firmware != "33.011" {
		t.Fatalf("asset = %+v", a)
	}
	a, _ = assetForMatching(&models.DeviceInfo{Vendor: "OUI Name", Asset: &models.AssetInfo{Vendor: "Siemens AG", Model: "S7-1500"}})
	if a.Vendor != "Siemens AG" {
		t.Fatalf("reported vendor replaced: %+v", a)
	}
}
