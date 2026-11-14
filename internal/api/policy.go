package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/policy"
)

// MinAPITokenLength is the shortest CERBERUS_API_TOKEN accepted.
const MinAPITokenLength = 16

const maxPolicyBody = 16 << 10

// SetPolicy enables the /api/v1/policy endpoints. Call before Handler.
func (s *Server) SetPolicy(e *policy.Engine) {
	s.policy = e
}

// SetAPIToken sets the bearer token required for state-changing requests.
// An empty token keeps those endpoints disabled. Call before Handler.
func (s *Server) SetAPIToken(token string) error {
	if token != "" && len(token) < MinAPITokenLength {
		return fmt.Errorf("API token must be at least %d characters", MinAPITokenLength)
	}
	if token == "" {
		s.tokenHash = nil
		return nil
	}
	h := sha256.Sum256([]byte(token))
	s.tokenHash = h[:]
	return nil
}

func (s *Server) registerPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/policy", s.handlePolicyStatus)
	mux.Handle("PUT /api/v1/policy/mode", s.requireToken(http.HandlerFunc(s.handlePolicyMode)))
	mux.Handle("POST /api/v1/policy/rules", s.requireToken(http.HandlerFunc(s.handlePolicyAdd)))
	mux.Handle("DELETE /api/v1/policy/rules/{id}", s.requireToken(http.HandlerFunc(s.handlePolicyDelete)))

	mux.HandleFunc("GET /api/v1/policy/log", s.handlePolicyLog)
	mux.Handle("POST /api/v1/policy/filters", s.requireToken(http.HandlerFunc(s.handleFilterAdd)))
	mux.Handle("DELETE /api/v1/policy/filters/{id}", s.requireToken(http.HandlerFunc(s.handleFilterDelete)))
	mux.Handle("PUT /api/v1/policy/filters/{id}/position", s.requireToken(http.HandlerFunc(s.handleFilterMove)))
	mux.Handle("PUT /api/v1/policy/filters/{id}/enabled", s.requireToken(http.HandlerFunc(s.handleFilterEnabled)))
}

func (s *Server) handlePolicyLog(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, s.policy.Logs(limit))
}

func (s *Server) handleFilterAdd(w http.ResponseWriter, r *http.Request) {
	var in policy.FilterInput
	if !decodeBody(w, r, &in) {
		return
	}
	rule, err := s.policy.AddFilter(in, actor(r))
	if err != nil {
		writePolicyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleFilterDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.policy.RemoveFilter(r.PathValue("id"), actor(r)); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleFilterMove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Position *int `json:"position"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Position == nil {
		writeError(w, http.StatusBadRequest, "position is required")
		return
	}
	if err := s.policy.MoveFilter(r.PathValue("id"), *body.Position, actor(r)); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleFilterEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	if err := s.policy.SetFilterEnabled(r.PathValue("id"), *body.Enabled, actor(r)); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type policyStatusResponse struct {
	policy.Status
	// WritesEnabled tells the console whether a token is configured.
	WritesEnabled bool `json:"writes_enabled"`
}

func (s *Server) handlePolicyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, policyStatusResponse{Status: s.policy.Status(), WritesEnabled: s.tokenHash != nil})
}

func (s *Server) handlePolicyMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode policy.Mode `json:"mode"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if err := s.policy.SetMode(body.Mode, actor(r)); err != nil {
		writePolicyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]policy.Mode{"mode": s.policy.Mode()})
}

func (s *Server) handlePolicyAdd(w http.ResponseWriter, r *http.Request) {
	var in policy.RuleInput
	if !decodeBody(w, r, &in) {
		return
	}
	rule, err := s.policy.Add(in, actor(r))
	if err != nil {
		writePolicyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.policy.Remove(r.PathValue("id"), actor(r)); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeBody reads a small JSON body strictly (unknown fields rejected).
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return false
	}
	return true
}

func writePolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policy.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, policy.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, policy.ErrProtected):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, policy.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, policy.ErrFull):
		writeError(w, http.StatusConflict, err.Error())
	default:
		// Kernel or storage failure: the change was rolled back.
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// actor names who made a change in the audit log: an optional
// X-Cerberus-Actor label (sanitised) plus the client address.
func actor(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	label := sanitizeLabel(r.Header.Get("X-Cerberus-Actor"))
	if label == "" {
		label = "api"
	}
	return label + "@" + host
}

func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, c := range strings.TrimSpace(s) {
		if b.Len() >= 64 {
			break
		}
		if c == '-' || c == '_' || c == '.' || c == '@' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// requireToken guards state-changing endpoints with a bearer token. A
// header token (not a cookie) also rules out CSRF from other sites.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.policy == nil {
			writeError(w, http.StatusNotFound, "policy engine not enabled")
			return
		}
		if s.tokenHash == nil {
			writeError(w, http.StatusForbidden, "policy changes are disabled: set CERBERUS_API_TOKEN")
			return
		}
		client := clientIP(r)
		if !s.authLimit.allow(client) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(got[:], s.tokenHash) != 1 {
			s.authLimit.fail(client)
			w.Header().Set("WWW-Authenticate", `Bearer realm="cerberus"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authLimiter allows authFailBudget failed attempts per client per window.
type authLimiter struct {
	mu       sync.Mutex
	failures map[string]*failWindow
	now      func() time.Time
}

type failWindow struct {
	start time.Time
	count int
}

const (
	authFailBudget = 10
	authFailWindow = time.Minute
	authMaxClients = 4096
)

func (l *authLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *authLimiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.failures[client]
	if f == nil {
		return true
	}
	if l.clock().Sub(f.start) >= authFailWindow {
		delete(l.failures, client)
		return true
	}
	return f.count < authFailBudget
}

func (l *authLimiter) fail(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = make(map[string]*failWindow)
	}
	now := l.clock()
	f := l.failures[client]
	if f == nil || now.Sub(f.start) >= authFailWindow {
		if len(l.failures) >= authMaxClients {
			for k, v := range l.failures {
				if now.Sub(v.start) >= authFailWindow {
					delete(l.failures, k)
				}
			}
			if len(l.failures) >= authMaxClients {
				clear(l.failures)
			}
		}
		l.failures[client] = &failWindow{start: now, count: 1}
		return
	}
	f.count++
}
