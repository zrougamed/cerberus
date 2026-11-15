package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestParseRole(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]Role{"viewer": RoleViewer, " Analyst ": RoleAnalyst, "ADMIN": RoleAdmin} {
		if r, ok := ParseRole(in); !ok || r != want {
			t.Errorf("ParseRole(%q) = %v %v", in, r, ok)
		}
	}
	for _, bad := range []string{"", "none", "root"} {
		if _, ok := ParseRole(bad); ok {
			t.Errorf("ParseRole(%q) accepted", bad)
		}
	}
	if RoleAnalyst.String() != "analyst" || RoleNone.String() != "none" {
		t.Fatal("role names")
	}
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	secret := writeFile(t, "secret", "s3cret\n")
	good := `
protect_reads: true
tokens:
  - {name: prometheus, role: viewer, sha256: ` + sha("p") + `}
oidc:
  issuer: https://idp.example
  client_id: cerberus
  redirect_url: https://cerberus.example/auth/callback
  client_secret_file: ` + secret + `
  roles:
    admin: [ot-admins]
    analyst: [soc, ot-admins]
`
	c, err := LoadConfig(writeFile(t, "auth.yaml", good))
	if err != nil {
		t.Fatal(err)
	}
	o := c.OIDC
	if !c.ProtectReads || o.clientSecret != "s3cret" || o.GroupsClaim != "groups" || o.SessionHours != 8 ||
		o.roleGroups["ot-admins"] != RoleAdmin || o.roleGroups["soc"] != RoleAnalyst || len(o.Scopes) != 3 {
		t.Fatalf("config = %+v %+v", c, o)
	}
	t.Setenv("CERBERUS_OIDC_CLIENT_SECRET", "from-env")
	c, _ = LoadConfig(writeFile(t, "auth.yaml", good))
	if c.OIDC.clientSecret != "from-env" {
		t.Fatal("env secret should win")
	}
}

// The shipped example must stay loadable.
func TestLoadConfig_Example(t *testing.T) {
	c, err := LoadConfig("../../configs/auth.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tokens) != 2 || c.OIDC != nil || c.ProtectReads {
		t.Fatalf("example config = %+v", c)
	}
}

func TestLoadConfig_Errors(t *testing.T) {
	t.Setenv("CERBERUS_OIDC_CLIENT_SECRET", "x")
	oidcBase := "oidc:\n  issuer: https://idp.example\n  client_id: c\n  redirect_url: https://h/auth/callback\n  roles: {admin: [a]}\n"
	tests := map[string]string{
		"unknown key":         "protect_read: true\n",
		"token no name":       "tokens: [{role: admin, sha256: " + sha("x") + "}]\n",
		"duplicate token":     "tokens: [{name: a, role: admin, sha256: " + sha("x") + "}, {name: a, role: viewer, sha256: " + sha("y") + "}]\n",
		"token bad role":      "tokens: [{name: a, role: root, sha256: " + sha("x") + "}]\n",
		"token bad hash":      "tokens: [{name: a, role: admin, sha256: abc}]\n",
		"http issuer":         strings.Replace(oidcBase, "https://idp", "http://idp", 1),
		"no client id":        strings.Replace(oidcBase, "client_id: c", "client_id: \"\"", 1),
		"wrong redirect path": strings.Replace(oidcBase, "/auth/callback", "/cb", 1),
		"http redirect":       strings.Replace(oidcBase, "https://h/", "http://h/", 1),
		"http lookalike":      strings.Replace(oidcBase, "https://h/", "http://localhost.evil.example/", 1),
		"removed key":         oidcBase + "  insecure_cookie: true\n",
		"bad role name":       strings.Replace(oidcBase, "{admin: [a]}", "{root: [a]}", 1),
		"no roles":            strings.Replace(oidcBase, "  roles: {admin: [a]}\n", "", 1),
		"bad default role":    oidcBase + "  default_role: root\n",
		"session hours":       oidcBase + "  session_hours: 1000\n",
		"not yaml":            "{{",
	}
	for name, body := range tests {
		if _, err := LoadConfig(writeFile(t, "a.yaml", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig("/nonexistent/auth.yaml"); err == nil {
		t.Error("missing file accepted")
	}
	// Default role alone is enough; plain http only for loopback hosts.
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080"} {
		ok := "oidc:\n  issuer: https://idp.example\n  client_id: c\n  redirect_url: http://" + host + "/auth/callback\n  default_role: viewer\n"
		if _, err := LoadConfig(writeFile(t, "a.yaml", ok)); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	t.Setenv("CERBERUS_OIDC_CLIENT_SECRET", "")
	if _, err := LoadConfig(writeFile(t, "a.yaml", oidcBase)); err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("missing secret: %v", err)
	}
	if _, err := LoadConfig(writeFile(t, "a.yaml", oidcBase+"  client_secret_file: /nonexistent/s\n")); err == nil {
		t.Error("missing secret file accepted")
	}
	many := "tokens:\n"
	for i := range maxTokens + 1 {
		many += "  - {name: t" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i)}) + ", role: viewer, sha256: " + sha("x") + "}\n"
	}
	if _, err := LoadConfig(writeFile(t, "a.yaml", many)); err == nil {
		t.Error("too many tokens accepted")
	}
}

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestResolve_Tokens(t *testing.T) {
	t.Parallel()
	a := New(Config{Tokens: []TokenConfig{{Name: "prom", Role: "viewer", SHA256: sha("prom-token")}}}, "admin-token")
	p, err := a.Resolve(bearer("admin-token"))
	if err != nil || p.Role != RoleAdmin || p.Name != AdminTokenName || p.Method != MethodToken {
		t.Fatalf("admin = %+v %v", p, err)
	}
	if p, _ := a.Resolve(bearer("prom-token")); p.Role != RoleViewer || p.Name != "prom" {
		t.Fatalf("named = %+v", p)
	}
	if _, err := a.Resolve(bearer("nope")); err != ErrBadToken {
		t.Fatalf("bad token err = %v", err)
	}
	r := bearer("")
	r.Header.Set("Authorization", "Basic abc")
	if _, err := a.Resolve(r); err != ErrBadToken {
		t.Fatalf("basic auth err = %v", err)
	}
	if p, err := a.Resolve(bearer("")); err != nil || p.Role != RoleNone {
		t.Fatalf("anonymous = %+v %v", p, err)
	}
	if !a.WritesEnabled() || a.ProtectReads() || a.OIDCEnabled() {
		t.Fatal("flags")
	}
	a.SetAdminToken("rotated")
	if _, err := a.Resolve(bearer("admin-token")); err != ErrBadToken {
		t.Fatal("old admin token still works")
	}
	if p, _ := a.Resolve(bearer("rotated")); p.Role != RoleAdmin {
		t.Fatal("new admin token refused")
	}
	if p, _ := a.Resolve(bearer("prom-token")); p.Role != RoleViewer {
		t.Fatal("named token lost on rotation")
	}
	a.SetAdminToken("")
	empty := New(Config{}, "")
	if empty.WritesEnabled() {
		t.Fatal("no credentials should disable writes")
	}
}

func TestSessions(t *testing.T) {
	t.Parallel()
	s := newSessionStore()
	now := time.Now()
	id, sess := s.create("alice", RoleAnalyst, time.Hour, now)
	got, ok := s.get(id, now.Add(time.Minute))
	if !ok || got.name != "alice" || got.csrf != sess.csrf || len(got.csrf) != 64 {
		t.Fatalf("session = %+v %v", got, ok)
	}
	if _, ok := s.get(id, now.Add(2*time.Hour)); ok {
		t.Fatal("expired session accepted")
	}
	if _, ok := s.get(id, now); ok {
		t.Fatal("expired session not removed")
	}
	id2, _ := s.create("bob", RoleViewer, time.Hour, now)
	s.delete(id2)
	if _, ok := s.get(id2, now); ok {
		t.Fatal("deleted session accepted")
	}
	// At the cap, expired sessions go first, then the oldest.
	for i := range maxSessions {
		s.create("u", RoleViewer, time.Duration(i+1)*time.Second, now)
	}
	newest, _ := s.create("last", RoleViewer, time.Hour, now)
	if _, ok := s.get(newest, now); !ok || len(s.byID) > maxSessions {
		t.Fatalf("cap: %d sessions", len(s.byID))
	}
	s.create("after-expiry", RoleViewer, time.Hour, now.Add(time.Hour))
	if len(s.byID) > maxSessions {
		t.Fatal("sweep did not run")
	}
}

func TestCheckCSRF(t *testing.T) {
	t.Parallel()
	sessionP := Principal{Method: MethodSession, CSRF: "abc"}
	post := httptest.NewRequest(http.MethodPost, "/", nil)
	if CheckCSRF(sessionP, post) {
		t.Fatal("missing header accepted")
	}
	post.Header.Set(CSRFHeader, "abd")
	if CheckCSRF(sessionP, post) {
		t.Fatal("wrong header accepted")
	}
	post.Header.Set(CSRFHeader, "abc")
	if !CheckCSRF(sessionP, post) {
		t.Fatal("right header refused")
	}
	if !CheckCSRF(sessionP, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("reads need no CSRF")
	}
	if !CheckCSRF(Principal{Method: MethodToken}, httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("token callers need no CSRF")
	}
	ctx := WithPrincipal(post.Context(), sessionP)
	if p, ok := FromContext(ctx); !ok || p.CSRF != "abc" {
		t.Fatal("context round trip")
	}
	if _, ok := FromContext(post.Context()); ok {
		t.Fatal("empty context has a principal")
	}
}

// fakeIdP is a minimal OpenID provider: discovery, JWKS, authorize (not
// used by the browser here) and a token endpoint that checks PKCE.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	groups []string
	nonce  string // set from the authorize URL
	badSig bool
	// codes: code -> PKCE challenge
	codes map[string]string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: key, codes: map[string]string{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		challenge, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		groups, nonce, badSig := f.groups, f.nonce, f.badSig
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signKey := f.key
		if badSig {
			signKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		now := time.Now()
		raw, _ := jwt.Signed(sig).Claims(jwt.Claims{Issuer: f.srv.URL, Subject: "u-1", Audience: jwt.Audience{"cerberus"},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).
			Claims(map[string]any{"nonce": nonce, "preferred_username": "alice", "groups": groups}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})
	return f
}

func oidcAuth(t *testing.T, f *fakeIdP, mutate func(*OIDCConfig)) *Authenticator {
	t.Helper()
	t.Setenv("CERBERUS_OIDC_CLIENT_SECRET", "secret")
	cfg := &OIDCConfig{Issuer: f.srv.URL, ClientID: "cerberus", RedirectURL: "https://cerberus.example/auth/callback",
		Roles: map[string][]string{"admin": {"ot-admins"}, "viewer": {"operators"}}}
	if mutate != nil {
		mutate(cfg)
	}
	c := Config{OIDC: cfg}
	if err := PrepareForTest(&c); err != nil {
		t.Fatal(err)
	}
	return New(c, "", WithHTTPClient(f.srv.Client()), WithHTTPClient(nil))
}

// login runs /auth/login and the provider's side of the redirect, then
// returns the callback request the browser would make.
func login(t *testing.T, a *Authenticator, f *fakeIdP) *http.Request {
	t.Helper()
	rr := httptest.NewRecorder()
	a.LoginHandler(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rr.Code, rr.Body)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("client_id") != "cerberus" {
		t.Fatalf("authorize URL = %s", loc)
	}
	f.mu.Lock()
	f.nonce = q.Get("nonce")
	f.codes["code-1"] = q.Get("code_challenge")
	f.mu.Unlock()
	return httptest.NewRequest(http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(q.Get("state")), nil)
}

func TestOIDC_SignInSessionAndLogout(t *testing.T) {
	f := newFakeIdP(t)
	f.groups = []string{"operators", "ot-admins"}
	a := oidcAuth(t, f, nil)
	rr := httptest.NewRecorder()
	a.CallbackHandler(rr, login(t, a, f))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s", rr.Code, rr.Body)
	}
	cookie := rr.Result().Cookies()[0]
	if cookie.Name != SessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 8*3600 {
		t.Fatalf("cookie = %+v", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	req.AddCookie(cookie)
	p, err := a.Resolve(req)
	if err != nil || p.Name != "alice" || p.Role != RoleAdmin || p.Method != MethodSession || p.CSRF == "" {
		t.Fatalf("principal = %+v %v", p, err)
	}

	// Logout needs the CSRF header.
	out := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	out.AddCookie(cookie)
	rr = httptest.NewRecorder()
	a.LogoutHandler(rr, out)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", rr.Code)
	}
	out.Header.Set(CSRFHeader, p.CSRF)
	rr = httptest.NewRecorder()
	a.LogoutHandler(rr, out)
	if rr.Code != http.StatusNoContent || rr.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("logout: %d", rr.Code)
	}
	if p, _ := a.Resolve(req); p.Role != RoleNone {
		t.Fatal("session survived logout")
	}
}

func TestOIDC_Refusals(t *testing.T) {
	f := newFakeIdP(t)
	a := oidcAuth(t, f, nil)
	call := func(r *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		a.CallbackHandler(rr, r)
		return rr
	}

	f.groups = []string{"visitors"}
	if rr := call(login(t, a, f)); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "not in a group") {
		t.Fatalf("no role: %d %s", rr.Code, rr.Body)
	}

	f.groups = []string{"operators"}
	req := login(t, a, f)
	f.nonce = "different"
	if rr := call(req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch: %d", rr.Code)
	}

	req = login(t, a, f)
	f.badSig = true
	if rr := call(req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature: %d", rr.Code)
	}
	f.badSig = false

	req = login(t, a, f)
	if rr := call(req); rr.Code != http.StatusFound {
		t.Fatalf("good sign-in: %d", rr.Code)
	}
	if rr := call(req); rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed state: %d", rr.Code)
	}

	req = login(t, a, f)
	a.oidc.now = func() time.Time { return time.Now().Add(pendingTTL + time.Minute) }
	if rr := call(req); rr.Code != http.StatusBadRequest {
		t.Fatalf("expired state: %d", rr.Code)
	}
	a.oidc.now = time.Now

	if rr := call(httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)); rr.Code != http.StatusUnauthorized ||
		!strings.Contains(rr.Body.String(), "access_denied") {
		t.Fatalf("provider error: %d", rr.Code)
	}
	// A code the provider does not know (PKCE or replay) fails the exchange.
	req = login(t, a, f)
	f.mu.Lock()
	clear(f.codes)
	f.mu.Unlock()
	if rr := call(req); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unknown code: %d", rr.Code)
	}
}

func TestOIDC_DefaultRoleStringGroupsAndLocalhost(t *testing.T) {
	f := newFakeIdP(t)
	a := oidcAuth(t, f, func(c *OIDCConfig) {
		c.DefaultRole, c.SessionHours = "viewer", 2
		c.RedirectURL = "http://localhost:8080/auth/callback"
	})
	f.groups = nil
	rr := httptest.NewRecorder()
	a.CallbackHandler(rr, login(t, a, f))
	c := rr.Result().Cookies()[0]
	if rr.Code != http.StatusFound || !c.Secure || !c.HttpOnly || c.MaxAge != 7200 {
		t.Fatalf("callback %d cookie %+v", rr.Code, c)
	}
	if got := groupsFrom("solo"); len(got) != 1 || got[0] != "solo" {
		t.Fatal("string groups claim")
	}
	if got := groupsFrom([]any{"a", 3, "b"}); len(got) != 2 {
		t.Fatalf("mixed groups = %v", got)
	}
	if groupsFrom(42) != nil {
		t.Fatal("non-list groups")
	}
}

func TestOIDC_ProviderDownAndNotConfigured(t *testing.T) {
	f := newFakeIdP(t)
	a := oidcAuth(t, f, nil)
	f.srv.Close()
	rr := httptest.NewRecorder()
	a.LoginHandler(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("provider down: %d", rr.Code)
	}
	plain := New(Config{}, "t")
	for _, h := range []http.HandlerFunc{plain.LoginHandler, plain.CallbackHandler} {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodGet, "/auth/x", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("not configured: %d", rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	plain.LogoutHandler(rr, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("logout without session: %d", rr.Code)
	}
}

func TestOIDC_PendingCap(t *testing.T) {
	f := newFakeIdP(t)
	a := oidcAuth(t, f, nil)
	for range maxPending {
		rr := httptest.NewRecorder()
		a.LoginHandler(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	}
	rr := httptest.NewRecorder()
	a.LoginHandler(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("pending cap: %d", rr.Code)
	}
}
