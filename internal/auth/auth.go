package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Authentication methods.
const (
	MethodToken   = "token"
	MethodSession = "oidc"
)

// Cookie and header names used by the Control Room.
const (
	SessionCookie = "cerberus_session"
	CSRFHeader    = "X-Cerberus-CSRF"
)

// AdminTokenName names the CERBERUS_API_TOKEN principal.
const AdminTokenName = "api-token"

// ErrBadToken is returned for a bearer token that matches nothing.
var ErrBadToken = errors.New("invalid bearer token")

// Principal is the authenticated caller.
type Principal struct {
	Name   string `json:"name"`
	Role   Role   `json:"-"`
	Method string `json:"method"`
	CSRF   string `json:"-"` // session callers must echo it on changes
}

type namedToken struct {
	name string
	role Role
	hash [32]byte
}

// Authenticator resolves callers. Safe for concurrent use.
type Authenticator struct {
	mu       sync.RWMutex
	cfg      Config
	tokens   []namedToken
	sessions *sessionStore
	oidc     *oidcClient
}

// Option changes how an Authenticator is built.
type Option func(*Authenticator)

// WithHTTPClient sets the client used to reach the OIDC provider, for a
// private CA or an outbound proxy.
func WithHTTPClient(c *http.Client) Option {
	return func(a *Authenticator) {
		if a.oidc != nil && c != nil {
			a.oidc.http = c
		}
	}
}

// New builds an authenticator from the optional file config and the
// CERBERUS_API_TOKEN admin token (empty for none).
func New(cfg Config, adminToken string, opts ...Option) *Authenticator {
	a := &Authenticator{cfg: cfg, sessions: newSessionStore()}
	if adminToken != "" {
		a.tokens = append(a.tokens, namedToken{name: AdminTokenName, role: RoleAdmin, hash: sha256.Sum256([]byte(adminToken))})
	}
	for _, t := range cfg.Tokens {
		var h [32]byte
		b, _ := hex.DecodeString(t.SHA256) // validated by prepare
		copy(h[:], b)
		r, _ := ParseRole(t.Role)
		a.tokens = append(a.tokens, namedToken{name: t.Name, role: r, hash: h})
	}
	if cfg.OIDC != nil {
		a.oidc = newOIDCClient(cfg.OIDC, a.sessions)
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// PrepareForTest validates c the way LoadConfig does; for building configs
// in code (tests, embedding) without a file.
func PrepareForTest(c *Config) error { return c.prepare() }

// SetAdminToken replaces the CERBERUS_API_TOKEN admin token.
func (a *Authenticator) SetAdminToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.tokens[:0:0]
	for _, t := range a.tokens {
		if t.name != AdminTokenName {
			kept = append(kept, t)
		}
	}
	if token != "" {
		kept = append([]namedToken{{name: AdminTokenName, role: RoleAdmin, hash: sha256.Sum256([]byte(token))}}, kept...)
	}
	a.tokens = kept
}

// WritesEnabled reports whether anyone can authenticate at all.
func (a *Authenticator) WritesEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.tokens) > 0 || a.oidc != nil
}

// ProtectReads reports whether reads need a principal.
func (a *Authenticator) ProtectReads() bool { return a.cfg.ProtectReads }

// OIDCEnabled reports whether browser sign-in is configured.
func (a *Authenticator) OIDCEnabled() bool { return a.oidc != nil }

// Resolve identifies the caller from a bearer token or a session cookie.
// No credentials gives a principal with RoleNone; a bearer token that
// matches nothing gives ErrBadToken.
func (a *Authenticator) Resolve(r *http.Request) (Principal, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return Principal{}, ErrBadToken
		}
		got := sha256.Sum256([]byte(token))
		a.mu.RLock()
		defer a.mu.RUnlock()
		match := -1
		// Compare against every token so timing does not reveal which
		// one, or how many, exist.
		for i, t := range a.tokens {
			if subtle.ConstantTimeCompare(got[:], t.hash[:]) == 1 {
				match = i
			}
		}
		if match < 0 {
			return Principal{}, ErrBadToken
		}
		t := a.tokens[match]
		return Principal{Name: t.name, Role: t.role, Method: MethodToken}, nil
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		if s, ok := a.sessions.get(c.Value, time.Now()); ok {
			return Principal{Name: s.name, Role: s.role, Method: MethodSession, CSRF: s.csrf}, nil
		}
	}
	return Principal{}, nil
}

// CheckCSRF verifies the CSRF header for session callers on changes.
// Token callers are exempt: a header token cannot be sent by another site.
func CheckCSRF(p Principal, r *http.Request) bool {
	if p.Method != MethodSession || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	h := r.Header.Get(CSRFHeader)
	return h != "" && subtle.ConstantTimeCompare([]byte(h), []byte(p.CSRF)) == 1
}

type ctxKey struct{}

// WithPrincipal stores p in the request context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal stored by WithPrincipal.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// randomToken returns n random bytes hex-encoded.
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
