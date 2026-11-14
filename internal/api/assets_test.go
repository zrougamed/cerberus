package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

const assetTestToken = "assets-test-token-0123456789abcdef"

func newAssetServer(t *testing.T, token string) (*monitor.NetworkMonitor, http.Handler) {
	t.Helper()
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	client, plc := uint32(0x0900000A), uint32(0x0500000A)
	mon.TrackEvent(modbusTCPEvent(1, client, plc, 50000, 502, 0x03, 0, 0, 0, 1))
	mon.TrackEvent(modbusTCPEvent(5, plc, client, 502, 50000, 0x03, 2, 0, 7))
	// PLC answers Read Device Identification with a formula-looking model.
	model := "=HYPERLINK(1)"
	pdu := append([]byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x04, 'A', 'c', 'm', 'e', 0x05, byte(len(model))}, model...)
	mon.TrackEvent(modbusTCPEvent(5, plc, client, 502, 50000, pdu...))
	// A device with no industrial traffic must not be listed.
	mon.TrackEvent(&models.NetworkEvent{EventType: models.EVENT_TYPE_TCP, Protocol: 6, SrcMac: [6]byte{2, 0, 0, 0, 0, 9}, SrcIP: 0x0700000A, DstPort: 443})

	srv := NewServer(mon)
	if err := srv.SetAPIToken(token); err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return mon, h
}

func getAssets(t *testing.T, h http.Handler, query string) []assetEntry {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/assets"+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var out []assetEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAssets_ListAndFilter(t *testing.T) {
	_, h := newAssetServer(t, "")
	all := getAssets(t, h, "")
	if len(all) != 2 {
		t.Fatalf("assets = %+v", all)
	}
	byMAC := map[string]assetEntry{}
	for _, e := range all {
		byMAC[e.MAC] = e
	}
	plc := byMAC["02:00:00:00:00:05"]
	if plc.Role != monitor.RoleController || plc.RoleSource != "inferred" || plc.Asset == nil || plc.Asset.Vendor != "Acme" {
		t.Fatalf("plc = %+v", plc)
	}
	if hmi := byMAC["02:00:00:00:00:01"]; hmi.Role != monitor.RoleHMI || len(hmi.Protocols) != 1 || hmi.Protocols[0] != "modbus" {
		t.Fatalf("hmi = %+v", hmi)
	}
	if got := getAssets(t, h, "?role=controller"); len(got) != 1 || got[0].MAC != "02:00:00:00:00:05" {
		t.Fatalf("role filter = %+v", got)
	}
	if got := getAssets(t, h, "?protocol=dnp3"); len(got) != 0 {
		t.Fatalf("protocol filter = %+v", got)
	}
}

func TestAssets_CSVDefusesFormulas(t *testing.T) {
	_, h := newAssetServer(t, "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/assets?format=csv", nil))
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type = %q", ct)
	}
	rows, err := csv.NewReader(rr.Body).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows = %v err = %v", rows, err)
	}
	if rows[0][0] != "mac" || rows[0][6] != "model" {
		t.Fatalf("header = %v", rows[0])
	}
	var plcRow []string
	for _, r := range rows[1:] {
		if r[0] == "02:00:00:00:00:05" {
			plcRow = r
		}
	}
	if plcRow == nil || plcRow[6] != "'=HYPERLINK(1)" || plcRow[2] != "controller" {
		t.Fatalf("plc row = %v", plcRow)
	}
}

func TestCSVSafe(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"": "", "PLC": "PLC", "=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@SUM": "'@SUM", "\tx": "'\tx"} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func putRole(h http.Handler, mac, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/assets/"+mac+"/role", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAssetRole_Override(t *testing.T) {
	mon, h := newAssetServer(t, assetTestToken)
	rr := putRole(h, "02:00:00:00:00:01", assetTestToken, `{"role":"scada_server"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var e assetEntry
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Role != "scada_server" || e.RoleSource != "override" {
		t.Fatalf("entry = %+v", e)
	}
	if mon.GetStats()["02:00:00:00:00:01"].RoleOverride != "scada_server" {
		t.Fatal("override not stored")
	}
	// Upper-case MAC is normalised; empty role clears.
	if rr := putRole(h, "02:00:00:00:00:01", assetTestToken, `{"role":""}`); rr.Code != http.StatusOK {
		t.Fatalf("clear status %d", rr.Code)
	}
	if got := getAssets(t, h, "?role=hmi"); len(got) != 1 {
		t.Fatalf("role after clear = %+v", got)
	}
}

func TestAssetRole_Errors(t *testing.T) {
	_, h := newAssetServer(t, assetTestToken)
	tests := []struct {
		name, mac, token, body string
		status                 int
	}{
		{"no token", "02:00:00:00:00:01", "", `{"role":"hmi"}`, http.StatusUnauthorized},
		{"wrong token", "02:00:00:00:00:01", "wrong-token-wrong-token-wrong", `{"role":"hmi"}`, http.StatusUnauthorized},
		{"bad mac", "not-a-mac", assetTestToken, `{"role":"hmi"}`, http.StatusBadRequest},
		{"bad role", "02:00:00:00:00:01", assetTestToken, `{"role":"admin"}`, http.StatusBadRequest},
		{"unknown field", "02:00:00:00:00:01", assetTestToken, `{"role":"hmi","x":1}`, http.StatusBadRequest},
		{"unknown device", "02:00:00:00:00:77", assetTestToken, `{"role":"hmi"}`, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rr := putRole(h, tt.mac, tt.token, tt.body); rr.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.status, rr.Body)
			}
		})
	}
}

func TestAssetRole_DisabledWithoutToken(t *testing.T) {
	_, h := newAssetServer(t, "")
	rr := putRole(h, "02:00:00:00:00:01", "anything", `{"role":"hmi"}`)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "asset changes are disabled") {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
}
