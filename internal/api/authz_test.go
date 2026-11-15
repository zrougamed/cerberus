package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/auth"
	"github.com/zrougamed/cerberus/internal/auth/authtest"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

const (
	viewerToken  = "viewer-token-0123456789"
	analystToken = "analyst-token-0123456789"
	adminToken   = "admin-token-0123456789abcdef"
)

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newRoleServer(t *testing.T, protectReads bool) (*monitor.NetworkMonitor, http.Handler) {
	t.Helper()
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	mon.TrackEvent(modbusTCPEvent(1, 0x0900000A, 0x0500000A, 50000, 502, 0x06, 0, 1, 0, 3)) // raises modbus_write
	srv := NewServer(mon)
	srv.SetAuth(auth.New(auth.Config{ProtectReads: protectReads, Tokens: []auth.TokenConfig{
		{Name: "dashboard", Role: "viewer", SHA256: hash(viewerToken)},
		{Name: "soc-bot", Role: "analyst", SHA256: hash(analystToken)},
	}}, ""))
	if err := srv.SetAPIToken(adminToken); err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return mon, h
}

func TestRoles_Matrix(t *testing.T) {
	_, h := newRoleServer(t, false)
	tests := []struct {
		name, method, path, body string
		want                     map[string]int // token -> status
	}{
		{"approve flows (analyst)", http.MethodPost, "/api/v1/baseline/approve", `{"ids":["0123456789abcdef"]}`,
			map[string]int{viewerToken: 403, analystToken: 200, adminToken: 200}},
		{"relearn (admin)", http.MethodPost, "/api/v1/baseline/relearn", `{}`,
			map[string]int{viewerToken: 403, analystToken: 403, adminToken: 200}},
		{"zones (admin)", http.MethodDelete, "/api/v1/segmentation", "",
			map[string]int{viewerToken: 403, analystToken: 403, adminToken: 200}},
		{"asset role (analyst)", http.MethodPut, "/api/v1/assets/02:00:00:00:00:01/role", `{"role":"hmi"}`,
			map[string]int{viewerToken: 403, analystToken: 200, adminToken: 200}},
	}
	for _, tt := range tests {
		for token, status := range tt.want {
			rr := doJSON(h, tt.method, tt.path, token, tt.body)
			if rr.Code != status {
				t.Errorf("%s with %s: %d, want %d (%s)", tt.name, strings.SplitN(token, "-", 2)[0], rr.Code, status, rr.Body)
			}
			if status == 403 && !strings.Contains(rr.Body.String(), "your role") {
				t.Errorf("%s: 403 should name the role: %s", tt.name, rr.Body)
			}
		}
	}
	// Reads stay open without protect_reads.
	if rr := doJSON(h, http.MethodGet, "/api/v1/devices", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("open read: %d", rr.Code)
	}
}

func TestRoles_ProtectReads(t *testing.T) {
	_, h := newRoleServer(t, true)
	for _, path := range []string{"/api/v1/devices", "/metrics", "/api/v1/alerts"} {
		if rr := doJSON(h, http.MethodGet, path, "", ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anonymous: %d", path, rr.Code)
		}
		if rr := doJSON(h, http.MethodGet, path, viewerToken, ""); rr.Code != http.StatusOK {
			t.Fatalf("%s viewer: %d", path, rr.Code)
		}
	}
	// The SPA and the session endpoint stay reachable to show sign-in.
	if rr := doJSON(h, http.MethodGet, "/api/v1/session", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("session: %d", rr.Code)
	}
	if rr := doJSON(h, http.MethodGet, "/", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("index: %d", rr.Code)
	}
	if rr := doJSON(h, http.MethodGet, "/api/v1/devices", "bad-token-xxxxxxxx", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token read: %d", rr.Code)
	}
}

func TestSessionEndpoint(t *testing.T) {
	_, h := newRoleServer(t, false)
	var s sessionResponse
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/session", "", "").Body.Bytes(), &s)
	if s.Authenticated || s.Role != "none" || !s.WritesEnabled || s.OIDC || s.ProtectReads {
		t.Fatalf("anonymous session = %+v", s)
	}
	_ = json.Unmarshal(doJSON(h, http.MethodGet, "/api/v1/session", analystToken, "").Body.Bytes(), &s)
	if !s.Authenticated || s.Role != "analyst" || s.Name != "soc-bot" || s.Method != "token" || s.CSRF != "" {
		t.Fatalf("token session = %+v", s)
	}
	if rr := doJSON(h, http.MethodGet, "/api/v1/session", "nope-nope-nope-nope", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token session: %d", rr.Code)
	}
}

func TestAlertAck(t *testing.T) {
	mon, h := newRoleServer(t, false)
	var id string
	for _, a := range mon.GetAlerts() {
		if a.Rule == "modbus_write" {
			id = a.ID
		}
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/alerts/"+id+"/ack", viewerToken, `{"note":"x"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("viewer ack: %d", rr.Code)
	}
	rr := doJSON(h, http.MethodPost, "/api/v1/alerts/"+id+"/ack", analystToken, `{"note":"Planned recipe change, ticket 4411"}`)
	var a models.AlertEvent
	_ = json.Unmarshal(rr.Body.Bytes(), &a)
	if rr.Code != http.StatusOK || a.AckedBy != "soc-bot" || a.AckedAt == nil || a.Note != "Planned recipe change, ticket 4411" {
		t.Fatalf("ack: %d %+v", rr.Code, a)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/alerts/"+id+"/ack", analystToken, ""); rr.Code != http.StatusOK {
		t.Fatalf("ack without body: %d %s", rr.Code, rr.Body)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/alerts/missing/ack", analystToken, `{}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown alert: %d", rr.Code)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/alerts/"+id+"/ack", analystToken, `{"note":"`+strings.Repeat("x", 501)+`"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("long note: %d", rr.Code)
	}
	if rr := doJSON(h, http.MethodPost, "/api/v1/alerts/"+id+"/ack", "", `{}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous ack: %d", rr.Code)
	}
}

func TestActor_NamedPrincipalsCannotRelabel(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "192.0.2.7:4000"
	r.Header.Set("X-Cerberus-Actor", "someone-else")
	named := r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Name: "alice@plant.example", Role: auth.RoleAdmin}))
	if got := actor(named); got != "alice@plant.example@192.0.2.7" {
		t.Fatalf("named actor = %q", got)
	}
	shared := r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Name: auth.AdminTokenName, Role: auth.RoleAdmin}))
	if got := actor(shared); got != "someone-else@192.0.2.7" {
		t.Fatalf("shared token actor = %q", got)
	}
}

// TestOIDC_ThroughTheAPI signs in through the real handlers and checks the
// session cookie, the CSRF rule on changes, roles and logout.
func TestOIDC_ThroughTheAPI(t *testing.T) {
	idp := authtest.New(t, "cerberus")
	t.Setenv("CERBERUS_OIDC_CLIENT_SECRET", "secret")
	cfg := auth.Config{ProtectReads: true, OIDC: &auth.OIDCConfig{
		Issuer: idp.Server.URL, ClientID: "cerberus", RedirectURL: "https://cerberus.example/auth/callback",
		Roles: map[string][]string{"analyst": {"soc"}, "viewer": {"operators"}},
	}}
	if err := auth.PrepareForTest(&cfg); err != nil {
		t.Fatal(err)
	}
	mon, err := monitor.NewNetworkMonitor(10, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mon.Close() })
	srv := NewServer(mon)
	srv.SetAuth(auth.New(cfg, "", auth.WithHTTPClient(idp.Server.Client())))
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}

	idp.SetUser("dana", "soc")
	resp := idp.SignIn(t, h)
	if resp.StatusCode != http.StatusFound || len(resp.Cookies()) != 1 {
		t.Fatalf("sign-in: %d", resp.StatusCode)
	}
	cookie := resp.Cookies()[0]
	withCookie := func(method, path, csrf, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(cookie)
		if csrf != "" {
			req.Header.Set(auth.CSRFHeader, csrf)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	var s sessionResponse
	_ = json.Unmarshal(withCookie(http.MethodGet, "/api/v1/session", "", "").Body.Bytes(), &s)
	if !s.Authenticated || s.Name != "dana" || s.Role != "analyst" || s.Method != "oidc" || s.CSRF == "" || !s.OIDC || s.LoginURL != "/auth/login" {
		t.Fatalf("session = %+v", s)
	}
	if rr := withCookie(http.MethodGet, "/api/v1/devices", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("read with session: %d", rr.Code)
	}
	body := `{"ids":["0123456789abcdef"]}`
	if rr := withCookie(http.MethodPost, "/api/v1/baseline/approve", "", body); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), auth.CSRFHeader) {
		t.Fatalf("write without CSRF: %d %s", rr.Code, rr.Body)
	}
	if rr := withCookie(http.MethodPost, "/api/v1/baseline/approve", s.CSRF, body); rr.Code != http.StatusOK {
		t.Fatalf("write with CSRF: %d %s", rr.Code, rr.Body)
	}
	if rr := withCookie(http.MethodPost, "/api/v1/baseline/relearn", s.CSRF, `{}`); rr.Code != http.StatusForbidden {
		t.Fatalf("analyst relearn: %d", rr.Code)
	}
	if rr := withCookie(http.MethodPost, "/auth/logout", s.CSRF, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rr.Code)
	}
	if rr := withCookie(http.MethodGet, "/api/v1/devices", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("read after logout: %d", rr.Code)
	}

	// A user in no mapped group is refused at the callback.
	idp.SetUser("eve", "contractors")
	if resp := idp.SignIn(t, h); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
		t.Fatalf("unmapped user: %d", resp.StatusCode)
	}
	// Forged tokens are refused.
	idp.SetUser("mallory", "soc")
	idp.ForgeNextToken(false, true)
	if resp := idp.SignIn(t, h); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged signature: %d", resp.StatusCode)
	}
	idp.ForgeNextToken(true, false)
	if resp := idp.SignIn(t, h); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged nonce: %d", resp.StatusCode)
	}
}
