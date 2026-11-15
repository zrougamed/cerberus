package api

import (
	"github.com/zrougamed/cerberus/internal/auth"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/advisories"
	"github.com/zrougamed/cerberus/internal/models"
)

// staleAfter is when the console starts warning that the bundle is old.
const staleAfter = 90 * 24 * time.Hour

type advisoryState struct {
	mu      sync.RWMutex
	path    string
	index   *advisories.Index
	loadErr string
}

type advisoryStatus struct {
	Loaded      bool      `json:"loaded"`
	Path        string    `json:"path,omitempty"`
	GeneratedAt time.Time `json:"generated_at,omitempty"`
	Source      string    `json:"source,omitempty"`
	Advisories  int       `json:"advisories"`
	AgeDays     int       `json:"age_days"`
	Stale       bool      `json:"stale"`
	Error       string    `json:"error,omitempty"`
}

// LoadAdvisories reads the bundle at path and keeps the path for reloads.
// A failed load leaves matching off and is reported by the status endpoint.
func (s *Server) LoadAdvisories(path string) error {
	s.adv.mu.Lock()
	defer s.adv.mu.Unlock()
	s.adv.path = path
	idx, err := advisories.Load(path)
	if err != nil {
		s.adv.index, s.adv.loadErr = nil, err.Error()
		return err
	}
	s.adv.index, s.adv.loadErr = idx, ""
	return nil
}

func (s *Server) advisoryIndex() *advisories.Index {
	s.adv.mu.RLock()
	defer s.adv.mu.RUnlock()
	return s.adv.index
}

func (s *Server) registerAdvisoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/advisories", s.handleAdvisoryStatus)
	mux.Handle("POST /api/v1/advisories/reload", s.requireRole(auth.RoleAdmin, http.HandlerFunc(s.handleAdvisoryReload),
		"advisory reloads are disabled: set CERBERUS_API_TOKEN"))
	mux.HandleFunc("GET /api/v1/assets/{mac}/advisories", s.handleAssetAdvisories)
}

func (s *Server) advisoryStatus(now time.Time) advisoryStatus {
	s.adv.mu.RLock()
	defer s.adv.mu.RUnlock()
	st := advisoryStatus{Path: s.adv.path, Error: s.adv.loadErr}
	if s.adv.index != nil {
		info := s.adv.index.Info()
		age := now.Sub(info.GeneratedAt)
		st.Loaded, st.GeneratedAt, st.Source, st.Advisories = true, info.GeneratedAt, info.Source, info.Advisories
		st.AgeDays, st.Stale = int(age.Hours()/24), age > staleAfter
	}
	return st
}

func (s *Server) handleAdvisoryStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.advisoryStatus(time.Now()))
}

func (s *Server) handleAdvisoryReload(w http.ResponseWriter, _ *http.Request) {
	s.adv.mu.RLock()
	path := s.adv.path
	s.adv.mu.RUnlock()
	if path == "" {
		writeError(w, http.StatusConflict, "no advisory bundle configured: set CERBERUS_ADVISORIES_FILE")
		return
	}
	if err := s.LoadAdvisories(path); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "the bundle could not be loaded: "+err.Error())
		return
	}
	log.Printf("advisories: bundle reloaded")
	writeJSON(w, http.StatusOK, s.advisoryStatus(time.Now()))
}

// assetForMatching uses the reported identity, falling back to the OUI
// vendor when the device did not report one.
func assetForMatching(d *models.DeviceInfo) (advisories.Asset, bool) {
	if d.Asset == nil || d.Asset.Model == "" {
		return advisories.Asset{}, false
	}
	vendor := d.Asset.Vendor
	if vendor == "" || strings.HasPrefix(vendor, "CIP vendor") || strings.HasPrefix(vendor, "PROFINET vendor") || strings.HasPrefix(vendor, "BACnet vendor") {
		vendor = d.Vendor
	}
	return advisories.Asset{Vendor: vendor, Model: d.Asset.Model, Firmware: d.Asset.Firmware}, true
}

func (s *Server) matchDevice(d *models.DeviceInfo) []advisories.Match {
	idx := s.advisoryIndex()
	a, ok := assetForMatching(d)
	if idx == nil || !ok {
		return nil
	}
	return idx.Match(a)
}

func (s *Server) handleAssetAdvisories(w http.ResponseWriter, r *http.Request) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid MAC address")
		return
	}
	mac := strings.ToLower(hw.String())
	for _, d := range s.monitor.GetStats() {
		if d.MAC == mac {
			matches := s.matchDevice(d)
			if matches == nil {
				matches = []advisories.Match{}
			}
			writeJSON(w, http.StatusOK, matches)
			return
		}
	}
	writeError(w, http.StatusNotFound, "unknown device")
}
