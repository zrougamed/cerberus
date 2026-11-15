package api

import (
	"errors"
	"github.com/zrougamed/cerberus/internal/auth"
	"net/http"
	"strings"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/monitor"
)

// maxSegmentationBody fits the 1,000-prefix limit with room for names.
const maxSegmentationBody = 256 << 10

func (s *Server) registerSegmentationRoutes(mux *http.ServeMux) {
	const disabled = "zone changes are disabled: set CERBERUS_API_TOKEN"
	mux.HandleFunc("GET /api/v1/segmentation", s.handleSegmentation)
	mux.Handle("PUT /api/v1/segmentation", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleSegmentationPut), disabled))
	mux.Handle("DELETE /api/v1/segmentation", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleSegmentationReset), disabled))
}

// handleSegmentation returns the active zones, conduits and zone alert
// rules, and whether they come from the config file or were saved.
func (s *Server) handleSegmentation(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.monitor.GetSegmentation())
}

// handleSegmentationPut replaces the segmentation. It is validated like
// the config file and applied without a restart.
func (s *Server) handleSegmentationPut(w http.ResponseWriter, r *http.Request) {
	var body alerts.SegmentationConfig
	if !decodeBodyLimit(w, r, &body, maxSegmentationBody) {
		return
	}
	switch err := s.monitor.SetSegmentation(body); {
	case errors.Is(err, monitor.ErrInvalidSegmentation):
		// The caller knows it sent zones; return the reason only.
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), monitor.ErrInvalidSegmentation.Error()+": "))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.GetSegmentation())
}

// handleSegmentationReset drops saved changes and goes back to the config
// file's segmentation.
func (s *Server) handleSegmentationReset(w http.ResponseWriter, _ *http.Request) {
	if err := s.monitor.ResetSegmentation(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.GetSegmentation())
}
