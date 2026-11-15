// Package authtest runs a minimal OpenID Connect provider for tests:
// discovery, JWKS, an authorize endpoint that signs the user in straight
// away, and a token endpoint that checks PKCE and returns RS256 ID tokens.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP is a fake provider. Change its fields between sign-ins to steer the
// next ID token.
type IdP struct {
	Server   *httptest.Server
	ClientID string
	// RedirectURL is the only redirect_uri the provider accepts, like a
	// registered client at a real provider.
	RedirectURL string

	mu     sync.Mutex
	key    *rsa.PrivateKey
	user   string
	groups []string
	nonce  string // override the nonce in the next token
	badSig bool
	codes  map[string]pending
}

type pending struct{ challenge, nonce string }

// New starts a TLS provider; use Server.Client() to trust it.
func New(t *testing.T, clientID string) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &IdP{ClientID: clientID, RedirectURL: "https://cerberus.example/auth/callback", key: key, user: "alice", codes: map[string]pending{}}
	mux := http.NewServeMux()
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	return f
}

// SetUser sets the next user's name and groups.
func (f *IdP) SetUser(name string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user, f.groups = name, groups
}

// ForgeNextToken makes the next ID token carry a wrong nonce, a bad
// signature, or both.
func (f *IdP) ForgeNextToken(wrongNonce, badSignature bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if wrongNonce {
		f.nonce = "forged"
	}
	f.badSig = badSignature
}

// ForgetCodes drops issued codes, so the next exchange fails.
func (f *IdP) ForgetCodes() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.codes)
}

func (f *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	u := f.Server.URL
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
		"jwks_uri": u + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

// authorize signs the user in immediately and redirects back with a code.
func (f *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != f.ClientID || q.Get("redirect_uri") != f.RedirectURL {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = pending{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	f.mu.Unlock()
	v := url.Values{"code": {code}, "state": {q.Get("state")}}
	http.Redirect(w, r, f.RedirectURL+"?"+v.Encode(), http.StatusFound)
}

func (f *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	p, ok := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	user, groups, nonce, badSig := f.user, f.groups, p.nonce, f.badSig
	if f.nonce != "" {
		nonce, f.nonce = f.nonce, ""
	}
	f.badSig = false
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	key := f.key
	if badSig {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	now := time.Now()
	raw, _ := jwt.Signed(sig).Claims(jwt.Claims{Issuer: f.Server.URL, Subject: "sub-" + user, Audience: jwt.Audience{f.ClientID},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).
		Claims(map[string]any{"nonce": nonce, "preferred_username": user, "groups": groups}).Serialize()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
}

// SignIn plays the browser: GET /auth/login on Cerberus, follow the
// provider's redirect, then the callback. It returns the final response
// from Cerberus (a redirect to "/" with a session cookie on success).
func (f *IdP) SignIn(t *testing.T, cerberus http.Handler) *http.Response {
	t.Helper()
	rr := httptest.NewRecorder()
	cerberus.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rr.Code, rr.Body)
	}
	client := f.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))
	cb := httptest.NewRecorder()
	cerberus.ServeHTTP(cb, httptest.NewRequest(http.MethodGet, back.RequestURI(), nil))
	return cb.Result()
}
