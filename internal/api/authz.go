package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/zrougamed/cerberus/internal/auth"
)

// SetAuth replaces the authenticator (named tokens, OIDC, protect_reads).
// Call before Handler; SetAPIToken still sets the admin token on it.
func (s *Server) SetAuth(a *auth.Authenticator) {
	s.auth = a
}

// principal resolves the caller, counting failed bearer tokens against the
// client's rate limit.
func (s *Server) principal(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	client := clientIP(r)
	if !s.authLimit.allow(client) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
		return auth.Principal{}, false
	}
	p, err := s.auth.Resolve(r)
	if err != nil {
		s.authLimit.fail(client)
		w.Header().Set("WWW-Authenticate", `Bearer realm="cerberus"`)
		writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return auth.Principal{}, false
	}
	return p, true
}

// requireRole guards an endpoint: the caller needs at least min, and a
// browser session must send its CSRF token on changes. disabled is the
// error when no way to authenticate is configured at all.
func (s *Server) requireRole(min auth.Role, next http.Handler, disabled string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.WritesEnabled() {
			writeError(w, http.StatusForbidden, disabled)
			return
		}
		p, ok := s.principal(w, r)
		if !ok {
			return
		}
		if p.Role == auth.RoleNone {
			// Unauthenticated writes count against the budget, as before.
			s.authLimit.fail(clientIP(r))
			w.Header().Set("WWW-Authenticate", `Bearer realm="cerberus"`)
			writeError(w, http.StatusUnauthorized, "sign in or send a bearer token")
			return
		}
		if !auth.CheckCSRF(p, r) {
			writeError(w, http.StatusForbidden, "missing or wrong "+auth.CSRFHeader+" header; reload the page")
			return
		}
		if p.Role < min {
			writeError(w, http.StatusForbidden, fmt.Sprintf("your role (%s) cannot do this; it needs %s", p.Role, min))
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

// publicPaths stay readable when reads are protected: the session endpoint
// tells the console whether to show the sign-in screen.
var publicPaths = map[string]bool{"/api/v1/session": true}

// readGuard requires a viewer for API reads and /metrics when
// protect_reads is on. Changes are guarded per route by requireRole.
func (s *Server) readGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isRead := r.Method == http.MethodGet || r.Method == http.MethodHead
		guarded := strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics"
		if !s.auth.ProtectReads() || !isRead || !guarded || publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := s.principal(w, r)
		if !ok {
			return
		}
		if p.Role < auth.RoleViewer {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cerberus"`)
			writeError(w, http.StatusUnauthorized, "sign in or send a bearer token")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Name          string `json:"name,omitempty"`
	Role          string `json:"role"`
	Method        string `json:"method,omitempty"`
	CSRF          string `json:"csrf,omitempty"`
	OIDC          bool   `json:"oidc"`
	LoginURL      string `json:"login_url,omitempty"`
	ProtectReads  bool   `json:"protect_reads"`
	WritesEnabled bool   `json:"writes_enabled"`
}

// handleSession tells the console who it is talking as and how to sign in.
// A bearer token in the request is resolved too, so the console learns the
// role of a token the user pasted.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	resp := sessionResponse{
		Authenticated: p.Role != auth.RoleNone, Name: p.Name, Role: p.Role.String(), Method: p.Method,
		CSRF: p.CSRF, OIDC: s.auth.OIDCEnabled(), ProtectReads: s.auth.ProtectReads(), WritesEnabled: s.auth.WritesEnabled(),
	}
	if resp.OIDC {
		resp.LoginURL = "/auth/login"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/session", s.handleSession)
	mux.HandleFunc("GET /auth/login", s.auth.LoginHandler)
	mux.HandleFunc("GET /auth/callback", s.auth.CallbackHandler)
	mux.HandleFunc("POST /auth/logout", s.auth.LogoutHandler)
}
