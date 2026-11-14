package api

import (
	"encoding/csv"
	"errors"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
)

// assetEntry is one row of the asset inventory.
type assetEntry struct {
	MAC        string            `json:"mac"`
	IP         string            `json:"ip"`
	OUIVendor  string            `json:"oui_vendor,omitempty"`
	Role       string            `json:"role"`
	RoleSource string            `json:"role_source"` // inferred | override | ""
	Protocols  []string          `json:"protocols"`
	Asset      *models.AssetInfo `json:"asset,omitempty"`
	LastSeen   time.Time         `json:"last_seen"`
}

func (s *Server) registerAssetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/assets", s.handleAssets)
	mux.Handle("PUT /api/v1/assets/{mac}/role", s.requireAuth(http.HandlerFunc(s.handleAssetRole),
		"asset changes are disabled: set CERBERUS_API_TOKEN"))
}

func toAssetEntry(d *models.DeviceInfo) (assetEntry, bool) {
	if len(d.Industrial) == 0 && d.Asset == nil && d.RoleOverride == "" {
		return assetEntry{}, false
	}
	e := assetEntry{
		MAC: d.MAC, IP: d.IP, OUIVendor: d.Vendor, Asset: d.Asset, LastSeen: d.LastSeen,
		Protocols: slices.Sorted(func(yield func(string) bool) {
			for p := range d.Industrial {
				if !yield(p) {
					return
				}
			}
		}),
	}
	switch {
	case d.RoleOverride != "":
		e.Role, e.RoleSource = d.RoleOverride, "override"
	default:
		if e.Role = monitor.InferRole(d); e.Role != "" {
			e.RoleSource = "inferred"
		}
	}
	return e, true
}

// handleAssets lists devices seen speaking an industrial protocol or
// reporting an identity. ?role= and ?protocol= filter; ?format=csv
// returns a spreadsheet-safe CSV.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	role, proto := q.Get("role"), q.Get("protocol")
	out := []assetEntry{}
	for _, d := range s.monitor.GetStats() {
		e, ok := toAssetEntry(d)
		if !ok || (role != "" && e.Role != role) || (proto != "" && !slices.Contains(e.Protocols, proto)) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP || (out[i].IP == out[j].IP && out[i].MAC < out[j].MAC)
	})

	if q.Get("format") == "csv" {
		writeAssetsCSV(w, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func writeAssetsCSV(w http.ResponseWriter, rows []assetEntry) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cerberus-assets.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"mac", "ip", "role", "role_source", "protocols", "vendor", "model", "firmware", "serial", "device_type", "identity_source", "oui_vendor", "last_seen"})
	for _, e := range rows {
		a := e.Asset
		if a == nil {
			a = &models.AssetInfo{}
		}
		record := []string{e.MAC, e.IP, e.Role, e.RoleSource, strings.Join(e.Protocols, " "),
			a.Vendor, a.Model, a.Firmware, a.Serial, a.DeviceType, a.Source, e.OUIVendor,
			e.LastSeen.UTC().Format(time.RFC3339)}
		for i := range record {
			record[i] = csvSafe(record[i])
		}
		_ = cw.Write(record)
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formula injection: model and vendor strings
// come from the devices themselves.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) handleAssetRole(w http.ResponseWriter, r *http.Request) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid MAC address")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	mac := strings.ToLower(hw.String())
	switch err := s.monitor.SetRoleOverride(mac, body.Role); {
	case errors.Is(err, monitor.ErrInvalidRole):
		writeError(w, http.StatusBadRequest, err.Error()+"; use one of "+strings.Join(monitor.AssetRoles, ", ")+" or empty to clear")
		return
	case errors.Is(err, monitor.ErrUnknownDevice):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not store the role: "+err.Error())
		return
	}
	for _, d := range s.monitor.GetStats() {
		if d.MAC != mac {
			continue
		}
		// Log what was stored, not what was sent: the stored values are
		// a normalised MAC and a role from monitor.AssetRoles.
		log.Printf("assets: role of %s set to %q", d.MAC, d.RoleOverride)
		if e, ok := toAssetEntry(d); ok {
			writeJSON(w, http.StatusOK, e)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mac": d.MAC, "role": d.RoleOverride})
		return
	}
	writeError(w, http.StatusNotFound, "device left the inventory")
}
