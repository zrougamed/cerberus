package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// pendingTTL is how long a user has to finish signing in at the
	// provider.
	pendingTTL = 10 * time.Minute
	maxPending = 1000
	// providerTimeout bounds discovery and token exchange.
	providerTimeout = 10 * time.Second
)

type pendingLogin struct {
	nonce    string
	verifier string // PKCE
	created  time.Time
}

// oidcClient runs the authorization code flow with PKCE. The provider is
// discovered on first use, so Cerberus starts even if the identity
// provider is down.
type oidcClient struct {
	cfg      *OIDCConfig
	sessions *sessionStore
	http     *http.Client
	now      func() time.Time

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	pending  map[string]pendingLogin
}

func newOIDCClient(cfg *OIDCConfig, sessions *sessionStore) *oidcClient {
	return &oidcClient{cfg: cfg, sessions: sessions, http: &http.Client{Timeout: providerTimeout},
		now: time.Now, pending: map[string]pendingLogin{}}
}

func (c *oidcClient) ensure(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return nil
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, c.http), c.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("discover %s: %w", c.cfg.Issuer, err)
	}
	c.provider = p
	c.oauth = &oauth2.Config{ClientID: c.cfg.ClientID, ClientSecret: c.cfg.clientSecret, RedirectURL: c.cfg.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: c.cfg.Scopes}
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID})
	return nil
}

// LoginHandler sends the browser to the provider.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	c := a.oidc
	if c == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), providerTimeout)
	defer cancel()
	if err := c.ensure(ctx); err != nil {
		log.Printf("auth: %v", err)
		page(w, http.StatusServiceUnavailable, "The sign-in provider cannot be reached right now. Try again in a minute.")
		return
	}
	state, nonce, verifier := randomToken(32), randomToken(32), oauth2.GenerateVerifier()
	c.mu.Lock()
	now := c.now()
	for k, v := range c.pending {
		if now.Sub(v.created) > pendingTTL {
			delete(c.pending, k)
		}
	}
	if len(c.pending) >= maxPending {
		c.mu.Unlock()
		page(w, http.StatusServiceUnavailable, "Too many sign-ins in progress. Try again in a few minutes.")
		return
	}
	c.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, created: now}
	authURL := c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	c.mu.Unlock()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackHandler finishes sign-in: checks state, exchanges the code,
// verifies the ID token and nonce, maps groups to a role and starts a
// session.
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	c := a.oidc
	if c == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		page(w, http.StatusUnauthorized, "The sign-in provider refused the sign-in: "+e+".")
		return
	}
	c.mu.Lock()
	pl, ok := c.pending[q.Get("state")]
	delete(c.pending, q.Get("state")) // one use only
	c.mu.Unlock()
	if !ok || c.now().Sub(pl.created) > pendingTTL {
		page(w, http.StatusBadRequest, "This sign-in link has expired or was already used. Start again from the Control Room.")
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), c.http), providerTimeout)
	defer cancel()
	name, role, err := c.finish(ctx, q.Get("code"), pl)
	if err != nil {
		log.Printf("auth: sign-in failed: %v", err)
		var denied errDenied
		if errors.As(err, &denied) {
			page(w, http.StatusForbidden, "Your account is not in a group that may use Cerberus. Ask an administrator to add you.")
			return
		}
		page(w, http.StatusUnauthorized, "Sign-in could not be completed. Start again from the Control Room.")
		return
	}
	id, _ := c.sessions.create(name, role, c.cfg.sessionTTL(), c.now())
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(c.cfg.sessionTTL().Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

type errDenied struct{ user string }

func (e errDenied) Error() string { return fmt.Sprintf("%s has no role", e.user) }

func (c *oidcClient) finish(ctx context.Context, code string, pl pendingLogin) (string, Role, error) {
	if err := c.ensure(ctx); err != nil {
		return "", RoleNone, err
	}
	tok, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(pl.verifier))
	if err != nil {
		return "", RoleNone, fmt.Errorf("exchange code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", RoleNone, errors.New("no id_token in the token response")
	}
	idt, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return "", RoleNone, fmt.Errorf("verify id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(pl.nonce)) != 1 {
		return "", RoleNone, errors.New("id token nonce does not match")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", RoleNone, fmt.Errorf("read claims: %w", err)
	}
	name := idt.Subject
	for _, k := range []string{"preferred_username", "email", "name"} {
		if v, ok := claims[k].(string); ok && v != "" {
			name = v
			break
		}
	}
	role := c.cfg.defaultRole
	for _, g := range groupsFrom(claims[c.cfg.GroupsClaim]) {
		if r := c.cfg.roleGroups[g]; r > role {
			role = r
		}
	}
	if role == RoleNone {
		return "", RoleNone, errDenied{user: name}
	}
	return name, role, nil
}

// groupsFrom accepts a list of strings or a single string claim.
func groupsFrom(v any) []string {
	switch g := v.(type) {
	case string:
		return []string{g}
	case []any:
		out := make([]string, 0, len(g))
		for _, x := range g {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// LogoutHandler ends the session. It is a POST with the CSRF header.
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	p, _ := a.Resolve(r)
	if p.Method != MethodSession || !CheckCSRF(p, r) {
		http.Error(w, "not signed in", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		a.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// page writes a minimal HTML message for the sign-in redirects, which a
// browser shows directly.
func page(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>Cerberus sign-in</title><p>%s</p><p><a href=\"/\">Back to the Control Room</a></p>", html.EscapeString(msg))
}
