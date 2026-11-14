package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/zrougamed/cerberus/internal/monitor"
)

// maxFlowIDsPerRequest bounds approve/forget bodies.
const maxFlowIDsPerRequest = 1000

var flowIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type baselineResponse struct {
	Status monitor.BaselineStatus `json:"status"`
	Flows  []monitor.FlowEntry    `json:"flows"`
}

func (s *Server) registerBaselineRoutes(mux *http.ServeMux) {
	const disabled = "baseline changes are disabled: set CERBERUS_API_TOKEN"
	mux.HandleFunc("GET /api/v1/baseline", s.handleBaseline)
	mux.Handle("POST /api/v1/baseline/approve", s.requireAuth(http.HandlerFunc(s.handleBaselineApprove), disabled))
	mux.Handle("POST /api/v1/baseline/forget", s.requireAuth(http.HandlerFunc(s.handleBaselineForget), disabled))
	mux.Handle("POST /api/v1/baseline/relearn", s.requireAuth(http.HandlerFunc(s.handleBaselineRelearn), disabled))
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "", monitor.FlowLearned, monitor.FlowApproved, monitor.FlowNew:
	default:
		writeError(w, http.StatusBadRequest, "status must be learned, approved or new")
		return
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, baselineResponse{
		Status: s.monitor.GetBaselineStatus(),
		Flows:  s.monitor.GetBaselineFlows(status, limit),
	})
}

// decodeFlowIDs reads {"ids": [...]} and validates every id.
func decodeFlowIDs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !decodeBody(w, r, &body) {
		return nil, false
	}
	if len(body.IDs) == 0 || len(body.IDs) > maxFlowIDsPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("ids must hold 1 to %d flow ids", maxFlowIDsPerRequest))
		return nil, false
	}
	for _, id := range body.IDs {
		if !flowIDPattern.MatchString(id) {
			writeError(w, http.StatusBadRequest, "flow ids are 16 lowercase hex characters")
			return nil, false
		}
	}
	return body.IDs, true
}

func (s *Server) baselineEnabled(w http.ResponseWriter) bool {
	if s.monitor.GetBaselineStatus().State == monitor.BaselineDisabled {
		writeError(w, http.StatusConflict, "the flow baseline is disabled in the alerts config")
		return false
	}
	return true
}

func (s *Server) handleBaselineApprove(w http.ResponseWriter, r *http.Request) {
	if !s.baselineEnabled(w) {
		return
	}
	if ids, ok := decodeFlowIDs(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]int{"approved": s.monitor.ApproveFlows(ids)})
	}
}

func (s *Server) handleBaselineForget(w http.ResponseWriter, r *http.Request) {
	if !s.baselineEnabled(w) {
		return
	}
	if ids, ok := decodeFlowIDs(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]int{"forgotten": s.monitor.ForgetFlows(ids)})
	}
}

func (s *Server) handleBaselineRelearn(w http.ResponseWriter, _ *http.Request) {
	if !s.monitor.RelearnBaseline() {
		writeError(w, http.StatusConflict, "the flow baseline is disabled in the alerts config")
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.GetBaselineStatus())
}
