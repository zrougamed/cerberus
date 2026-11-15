package api

import (
	"errors"
	"fmt"
	"github.com/zrougamed/cerberus/internal/auth"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/zrougamed/cerberus/internal/capture"
)

type capturesResponse struct {
	capture.Status
	Captures []capture.Capture `json:"captures"`
}

// SetCapture enables the packet capture endpoints. Safe to call after
// Handler.
func (s *Server) SetCapture(c *capture.Capturer) {
	s.capture.Store(c)
}

func (s *Server) registerCaptureRoutes(mux *http.ServeMux) {
	const disabled = "capture changes and downloads are disabled: set CERBERUS_API_TOKEN"
	mux.HandleFunc("GET /api/v1/captures", s.handleCaptures)
	// Captures hold full packet payloads, so even reading one needs the token.
	mux.Handle("GET /api/v1/captures/{id}", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleCaptureDownload), disabled))
	mux.Handle("DELETE /api/v1/captures/{id}", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleCaptureDelete), disabled))
	mux.Handle("POST /api/v1/captures", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleCaptureNow), disabled))
}

// capturer returns the capturer, or writes 409 and returns nil.
func (s *Server) capturer(w http.ResponseWriter) *capture.Capturer {
	c := s.capture.Load()
	if c == nil {
		writeError(w, http.StatusConflict, "packet capture is disabled: set capture.enabled in the alerts config")
	}
	return c
}

func (s *Server) handleCaptures(w http.ResponseWriter, _ *http.Request) {
	c := s.capture.Load()
	if c == nil {
		writeJSON(w, http.StatusOK, capturesResponse{Status: capture.Status{Interfaces: []string{}}, Captures: []capture.Capture{}})
		return
	}
	writeJSON(w, http.StatusOK, capturesResponse{Status: c.Status(), Captures: c.List()})
}

func (s *Server) handleCaptureDownload(w http.ResponseWriter, r *http.Request) {
	c := s.capturer(w)
	if c == nil {
		return
	}
	f, meta, err := c.Open(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-pcapng")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cerberus-%s.pcapng"`, meta.ID))
	w.Header().Set("Content-Length", fmt.Sprint(meta.Bytes))
	_, _ = io.Copy(w, f)
}

func (s *Server) handleCaptureDelete(w http.ResponseWriter, r *http.Request) {
	c := s.capturer(w)
	if c == nil {
		return
	}
	switch err := c.Delete(r.PathValue("id")); {
	case errors.Is(err, capture.ErrNotFound):
		writeError(w, http.StatusNotFound, "capture not found")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not delete the capture: "+err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleCaptureNow writes the last `seconds` of buffered traffic, for one
// address when given.
func (s *Server) handleCaptureNow(w http.ResponseWriter, r *http.Request) {
	capt := s.capturer(w)
	if capt == nil {
		return
	}
	var body struct {
		Address string `json:"address"`
		Seconds int    `json:"seconds"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	var addr netip.Addr
	if body.Address != "" {
		a, err := netip.ParseAddr(body.Address)
		if err != nil {
			writeError(w, http.StatusBadRequest, "address must be an IPv4 or IPv6 address")
			return
		}
		addr = a
	}
	c, err := capt.CaptureNow(addr, time.Duration(body.Seconds)*time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}
