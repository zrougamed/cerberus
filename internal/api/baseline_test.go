package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/monitor"
)

// newEnforcingBaselineServer opens a monitor whose stored baseline finished
// learning an hour ago, then sends one Modbus write so a new flow exists.
func newEnforcingBaselineServer(t *testing.T, cfg alerts.Config) (*monitor.NetworkMonitor, http.Handler) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "t.db")
	db, err := buntdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	err = db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("flowbaseline:meta", fmt.Sprintf(`{"started_at":%q,"learning_until":%q}`, past, past), nil)
		return err
	})
	if err != nil || db.Close() != nil {
		t.Fatalf("seed: %v", err)
	}
	mon, err := monitor.NewNetworkMonitorWithAlerts(10, dbPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	mon.TrackEvent(modbusTCPEvent(1, 0x0900000A, 0x0500000A, 50000, 502, 0x06, 0, 1, 0, 3))

	srv := NewServer(mon)
	if err := srv.SetAPIToken(assetTestToken); err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return mon, h
}

func doJSON(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getBaseline(t *testing.T, h http.Handler, query string) baselineResponse {
	t.Helper()
	rr := doJSON(h, http.MethodGet, "/api/v1/baseline"+query, "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var out baselineResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBaselineAPI_ListApproveForgetRelearn(t *testing.T) {
	mon, h := newEnforcingBaselineServer(t, alerts.DefaultConfig())
	b := getBaseline(t, h, "?status=new")
	if b.Status.State != monitor.BaselineEnforcing || b.Status.New != 1 || len(b.Flows) != 1 {
		t.Fatalf("baseline = %+v", b)
	}
	f := b.Flows[0]
	if f.Client != "10.0.0.9" || f.Server != "10.0.0.5" || f.Protocol != "modbus" || f.Class != "write" {
		t.Fatalf("flow = %+v", f)
	}
	found := false
	for _, a := range mon.GetAlerts() {
		found = found || a.Rule == alerts.RuleBaselineNewFlow
	}
	if !found {
		t.Fatal("no baseline_new_flow alert")
	}

	rr := doJSON(h, http.MethodPost, "/api/v1/baseline/approve", assetTestToken, `{"ids":["`+f.ID+`"]}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"approved":1`) {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body)
	}
	if b := getBaseline(t, h, "?status=approved&limit=10"); len(b.Flows) != 1 {
		t.Fatalf("approved = %+v", b)
	}
	rr = doJSON(h, http.MethodPost, "/api/v1/baseline/forget", assetTestToken, `{"ids":["`+f.ID+`"]}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"forgotten":1`) {
		t.Fatalf("forget: %d %s", rr.Code, rr.Body)
	}
	rr = doJSON(h, http.MethodPost, "/api/v1/baseline/relearn", assetTestToken, `{}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"state":"learning"`) {
		t.Fatalf("relearn: %d %s", rr.Code, rr.Body)
	}

	scrape := httptest.NewRecorder()
	h.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{`cerberus_baseline_flows{status="new"} 0`, "cerberus_baseline_learning 1", "cerberus_baseline_dropped_total 0"} {
		if !strings.Contains(scrape.Body.String(), want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
}

func TestBaselineAPI_Validation(t *testing.T) {
	_, h := newEnforcingBaselineServer(t, alerts.DefaultConfig())
	many := `{"ids":[` + strings.TrimSuffix(strings.Repeat(`"0123456789abcdef",`, maxFlowIDsPerRequest+1), ",") + `]}`
	tests := []struct {
		name, method, path, token, body string
		status                          int
	}{
		{"bad status filter", http.MethodGet, "/api/v1/baseline?status=bogus", "", "", http.StatusBadRequest},
		{"bad limit", http.MethodGet, "/api/v1/baseline?limit=0", "", "", http.StatusBadRequest},
		{"no token", http.MethodPost, "/api/v1/baseline/approve", "", `{"ids":["0123456789abcdef"]}`, http.StatusUnauthorized},
		{"empty ids", http.MethodPost, "/api/v1/baseline/approve", assetTestToken, `{"ids":[]}`, http.StatusBadRequest},
		{"bad id", http.MethodPost, "/api/v1/baseline/forget", assetTestToken, `{"ids":["../etc"]}`, http.StatusBadRequest},
		{"too many ids", http.MethodPost, "/api/v1/baseline/forget", assetTestToken, many, http.StatusBadRequest},
		{"bad json", http.MethodPost, "/api/v1/baseline/approve", assetTestToken, `{`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rr := doJSON(h, tt.method, tt.path, tt.token, tt.body); rr.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tt.status, rr.Body)
			}
		})
	}
}

func TestBaselineAPI_Disabled(t *testing.T) {
	cfg := alerts.DefaultConfig()
	cfg.FlowBaseline.Enabled = false
	_, h := newEnforcingBaselineServer(t, cfg)
	if b := getBaseline(t, h, ""); b.Status.State != monitor.BaselineDisabled || len(b.Flows) != 0 {
		t.Fatalf("baseline = %+v", b)
	}
	for _, path := range []string{"/api/v1/baseline/approve", "/api/v1/baseline/forget", "/api/v1/baseline/relearn"} {
		if rr := doJSON(h, http.MethodPost, path, assetTestToken, `{"ids":["0123456789abcdef"]}`); rr.Code != http.StatusConflict {
			t.Fatalf("%s: status %d", path, rr.Code)
		}
	}
	scrape := httptest.NewRecorder()
	h.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(scrape.Body.String(), "cerberus_baseline_flows") {
		t.Fatal("baseline metrics emitted while disabled")
	}
}
