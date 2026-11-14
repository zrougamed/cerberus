package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/policy"
)

const testToken = "s3cret-token-for-tests"

func newPolicyHandler(t *testing.T, token string) (http.Handler, *policy.Engine) {
	t.Helper()
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	eng, err := policy.Open(policy.Options{StatePath: filepath.Join(t.TempDir(), "policy.json")})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(mon)
	srv.SetPolicy(eng)
	if err := srv.SetAPIToken(token); err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return h, eng
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Cerberus-Actor", "alice<script>")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSetAPIToken_RejectsShortToken(t *testing.T) {
	srv := NewServer(nil)
	if err := srv.SetAPIToken("short"); err == nil {
		t.Fatal("expected error for short token")
	}
	if err := srv.SetAPIToken(""); err != nil {
		t.Fatalf("empty token disables writes: %v", err)
	}
}

func TestPolicyAPI_WritesDisabledWithoutToken(t *testing.T) {
	h, _ := newPolicyHandler(t, "")
	rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", "anything", `{"action":"drop","cidr":"203.0.113.1"}`)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "CERBERUS_API_TOKEN") {
		t.Fatalf("got %d %s", rr.Code, rr.Body)
	}
	rr = do(t, h, http.MethodGet, "/api/v1/policy", "", "")
	var st policyStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("status: %d %v", rr.Code, err)
	}
	if st.WritesEnabled || st.Mode != policy.ModeMonitor {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestPolicyAPI_AuthAndThrottling(t *testing.T) {
	h, _ := newPolicyHandler(t, testToken)
	body := `{"action":"drop","cidr":"203.0.113.1"}`
	if rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", "", body); rr.Code != http.StatusUnauthorized ||
		rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing token: %d", rr.Code)
	}
	for i := 1; i < authFailBudget; i++ {
		if rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", "wrong-token-xxxxxxxx", body); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rr.Code)
		}
	}
	// Budget exhausted: even the right token is refused for this client.
	rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", testToken, body)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestAuthLimiter_WindowResets(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	l := &authLimiter{now: func() time.Time { return now }}
	for range authFailBudget {
		l.fail("10.0.0.1")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("budget should be exhausted")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("other clients are not affected")
	}
	now = now.Add(authFailWindow)
	if !l.allow("10.0.0.1") {
		t.Fatal("window should reset")
	}
}

func TestPolicyAPI_RuleLifecycle(t *testing.T) {
	h, _ := newPolicyHandler(t, testToken)

	rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", testToken,
		`{"id":"c2","action":"drop","cidr":"203.0.113.0/24","direction":"dst","ttl_seconds":3600,"comment":"intel feed"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	var created policy.Rule
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	if created.ID != "c2" || created.ExpiresAt == nil || created.CreatedBy != "alicescript@192.0.2.1" {
		t.Fatalf("created: %+v", created)
	}

	cases := []struct {
		name, body string
		want       int
	}{
		{"duplicate", `{"id":"c2","action":"drop","cidr":"198.51.100.0/24"}`, http.StatusConflict},
		{"invalid", `{"action":"drop","cidr":"0.0.0.0/0"}`, http.StatusBadRequest},
		{"unknown field", `{"action":"drop","cidr":"10.0.0.1","verdict":"x"}`, http.StatusBadRequest},
		{"trailing data", `{"action":"drop","cidr":"10.0.0.1"} {}`, http.StatusBadRequest},
		{"not json", `drop everything`, http.StatusBadRequest},
		{"too large", `{"action":"drop","cidr":"10.0.0.1","comment":"` + strings.Repeat("x", maxPolicyBody) + `"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if rr := do(t, h, http.MethodPost, "/api/v1/policy/rules", testToken, tc.body); rr.Code != tc.want {
			t.Errorf("%s: got %d %s, want %d", tc.name, rr.Code, rr.Body, tc.want)
		}
	}

	if rr := do(t, h, http.MethodPut, "/api/v1/policy/mode", testToken, `{"mode":"enforce"}`); rr.Code != http.StatusOK {
		t.Fatalf("mode: %d %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, http.MethodPut, "/api/v1/policy/mode", testToken, `{"mode":"chaos"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", rr.Code)
	}

	rr = do(t, h, http.MethodGet, "/api/v1/policy", "", "")
	var st policyStatusResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if !st.WritesEnabled || st.Mode != policy.ModeEnforce || len(st.Rules) != 1 || len(st.Audit) != 2 {
		t.Fatalf("status: %+v", st)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("policy status must not be cached")
	}

	if rr := do(t, h, http.MethodDelete, "/api/v1/policy/rules/c2", testToken, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := do(t, h, http.MethodDelete, "/api/v1/policy/rules/c2", testToken, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rr.Code)
	}
	// Only DELETE is routed for a rule; GET falls through to the static
	// file server and must not succeed.
	if rr := do(t, h, http.MethodGet, "/api/v1/policy/rules/c2", testToken, ""); rr.Code < 400 {
		t.Fatalf("GET on rule path: %d", rr.Code)
	}
}

func TestWritePolicyError_StatusMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{policy.ErrNotFound, http.StatusNotFound},
		{policy.ErrConflict, http.StatusConflict},
		{policy.ErrProtected, http.StatusUnprocessableEntity},
		{policy.ErrInvalid, http.StatusBadRequest},
		{policy.ErrFull, http.StatusConflict},
		{errTest("kernel exploded"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		writePolicyError(rr, tc.err)
		if rr.Code != tc.want {
			t.Errorf("%v: got %d, want %d", tc.err, rr.Code, tc.want)
		}
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestPolicyAPI_NotRegisteredWithoutEngine(t *testing.T) {
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	h, _ := NewServer(mon).Handler()
	rr := do(t, h, http.MethodGet, "/api/v1/policy", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without engine, got %d", rr.Code)
	}
}

func TestFilterAPI_Lifecycle(t *testing.T) {
	h, eng := newPolicyHandler(t, testToken)

	if rr := do(t, h, http.MethodPost, "/api/v1/policy/filters", "", `{"verdict":"accept"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rr.Code)
	}
	body := `{"id":"ssh-drop","verdict":"drop","log":true,"match":{"protocol":"tcp","dst":"10.0.0.5","dst_port":"22"}}`
	rr := do(t, h, http.MethodPost, "/api/v1/policy/filters", testToken, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, http.MethodPost, "/api/v1/policy/filters", testToken, `{"id":"top","verdict":"accept","position":0,"match":{"protocol":"tcp","src":"10.0.0.99"}}`); rr.Code != http.StatusCreated {
		t.Fatalf("create at top: %d %s", rr.Code, rr.Body)
	}
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"broad drop needs force", http.MethodPost, "/api/v1/policy/filters", `{"verdict":"drop","match":{"protocol":"udp","dst_port":"53"}}`, http.StatusUnprocessableEntity},
		{"invalid matcher", http.MethodPost, "/api/v1/policy/filters", `{"verdict":"accept","match":{"protocol":"icmp","dst_port":"80"}}`, http.StatusBadRequest},
		{"unknown match field", http.MethodPost, "/api/v1/policy/filters", `{"verdict":"accept","match":{"ttl":4}}`, http.StatusBadRequest},
		{"duplicate id", http.MethodPost, "/api/v1/policy/filters", `{"id":"top","verdict":"accept"}`, http.StatusConflict},
		{"move", http.MethodPut, "/api/v1/policy/filters/ssh-drop/position", `{"position":0}`, http.StatusNoContent},
		{"move missing position", http.MethodPut, "/api/v1/policy/filters/ssh-drop/position", `{}`, http.StatusBadRequest},
		{"move out of range", http.MethodPut, "/api/v1/policy/filters/ssh-drop/position", `{"position":7}`, http.StatusBadRequest},
		{"move unknown", http.MethodPut, "/api/v1/policy/filters/nope/position", `{"position":0}`, http.StatusNotFound},
		{"disable", http.MethodPut, "/api/v1/policy/filters/top/enabled", `{"enabled":false}`, http.StatusNoContent},
		{"enabled missing", http.MethodPut, "/api/v1/policy/filters/top/enabled", `{}`, http.StatusBadRequest},
		{"bad log limit", http.MethodGet, "/api/v1/policy/log?limit=0", ``, http.StatusBadRequest},
		{"log", http.MethodGet, "/api/v1/policy/log?limit=5", ``, http.StatusOK},
	}
	for _, tc := range cases {
		if rr := do(t, h, tc.method, tc.path, testToken, tc.body); rr.Code != tc.want {
			t.Errorf("%s: got %d %s, want %d", tc.name, rr.Code, rr.Body, tc.want)
		}
	}

	var st policyStatusResponse
	rr = do(t, h, http.MethodGet, "/api/v1/policy", "", "")
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Filters) != 2 || st.Filters[0].ID != "ssh-drop" || st.Filters[1].Enabled || st.MaxFilters != policy.MaxFilterRules {
		t.Fatalf("status filters: %+v", st.Filters)
	}
	if st.Filters[0].Summary != "ipv4 tcp dst 10.0.0.5/32 dport 22" {
		t.Fatalf("summary: %q", st.Filters[0].Summary)
	}

	if rr := do(t, h, http.MethodDelete, "/api/v1/policy/filters/ssh-drop", testToken, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := do(t, h, http.MethodDelete, "/api/v1/policy/filters/ssh-drop", testToken, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rr.Code)
	}
	if n := len(eng.Status().Filters); n != 1 {
		t.Fatalf("filters left: %d", n)
	}
}
