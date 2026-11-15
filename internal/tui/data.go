package tui

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/zrougamed/cerberus/internal/models"
)

// API payloads the console shows. Devices, alerts and anomalies reuse the
// server's own models; the rest are the fields the screens need.

type summary struct {
	GeneratedAt          time.Time      `json:"generated_at"`
	PacketStats          map[string]int `json:"packet_stats"`
	DeviceCount          int            `json:"device_count"`
	TopServices          map[string]int `json:"top_services"`
	TopVendors           map[string]int `json:"top_vendors"`
	DNSQueryTypes        map[string]int `json:"dns_query_types"`
	DNSResponseCodes     map[string]int `json:"dns_response_codes"`
	DNSResponseDomains   map[string]int `json:"dns_response_domains"`
	EncryptedDNS         map[string]int `json:"encrypted_dns"`
	TLSVersions          map[string]int `json:"tls_versions"`
	TopTLSSNIs           map[string]int `json:"top_tls_snis"`
	DNSCorrelatedDomains map[string]int `json:"dns_correlated_domains"`
}

type session struct {
	Authenticated bool   `json:"authenticated"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	ProtectReads  bool   `json:"protect_reads"`
	WritesEnabled bool   `json:"writes_enabled"`
}

type version struct {
	Commit string `json:"commit"`
	Date   string `json:"date"`
}

type asset struct {
	MAC              string            `json:"mac"`
	IP               string            `json:"ip"`
	OUIVendor        string            `json:"oui_vendor"`
	Role             string            `json:"role"`
	RoleSource       string            `json:"role_source"`
	Protocols        []string          `json:"protocols"`
	Asset            *models.AssetInfo `json:"asset"`
	LastSeen         time.Time         `json:"last_seen"`
	Advisories       int               `json:"advisories"`
	AdvisorySeverity string            `json:"advisory_severity"`
}

type baselineFlow struct {
	ID        string    `json:"id"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	Protocol  string    `json:"protocol"`
	Class     string    `json:"class"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type baseline struct {
	Status struct {
		State         string    `json:"state"`
		StartedAt     time.Time `json:"started_at"`
		LearningUntil time.Time `json:"learning_until"`
		Learned       int       `json:"learned"`
		Approved      int       `json:"approved"`
		New           int       `json:"new"`
		Dropped       int       `json:"dropped"`
		MaxFlows      int       `json:"max_flows"`
	} `json:"status"`
	Flows []baselineFlow `json:"flows"`
}

type zoneInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Level      int      `json:"level"`
	CIDRs      []string `json:"cidrs"`
	Industrial bool     `json:"industrial"`
	Enforce    bool     `json:"enforce"`
	Devices    int      `json:"devices"`
}

type zones struct {
	Zones    []zoneInfo `json:"zones"`
	Conduits []struct {
		From          string `json:"from"`
		To            string `json:"to"`
		Ports         []int  `json:"ports"`
		Bidirectional bool   `json:"bidirectional"`
	} `json:"conduits"`
	Violations map[string]int `json:"violations"`
}

type counters struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type policyRule struct {
	ID        string   `json:"id"`
	Action    string   `json:"action"`
	MAC       string   `json:"mac"`
	CIDR      string   `json:"cidr"`
	Hostname  string   `json:"hostname"`
	HostMatch string   `json:"host_match"`
	Direction string   `json:"direction"`
	Comment   string   `json:"comment"`
	Counters  counters `json:"counters"`
}

type policyFilter struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Verdict  string   `json:"verdict"`
	Enabled  bool     `json:"enabled"`
	Comment  string   `json:"comment"`
	Counters counters `json:"counters"`
}

type auditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	RuleID string    `json:"rule_id"`
	Detail string    `json:"detail"`
}

type policy struct {
	Mode           string         `json:"mode"`
	KernelAttached bool           `json:"kernel_attached"`
	MaxRules       int            `json:"max_rules"`
	MaxFilters     int            `json:"max_filters"`
	Rules          []policyRule   `json:"rules"`
	Filters        []policyFilter `json:"filters"`
	Audit          []auditEntry   `json:"audit"`
}

type captureEntry struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"`
	Rule      string    `json:"rule"`
	Address   string    `json:"address"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Packets   int       `json:"packets"`
	Bytes     int64     `json:"bytes"`
	Drops     uint64    `json:"drops"`
}

type captures struct {
	Enabled       bool           `json:"enabled"`
	Interfaces    []string       `json:"interfaces"`
	BufferPackets int            `json:"buffer_packets"`
	BufferBytes   int64          `json:"buffer_bytes"`
	Pending       int            `json:"pending"`
	Skipped       int            `json:"skipped"`
	KernelDrops   uint64         `json:"kernel_drops"`
	Captures      []captureEntry `json:"captures"`
}

type advisoryStatus struct {
	Loaded      bool      `json:"loaded"`
	GeneratedAt time.Time `json:"generated_at"`
	Source      string    `json:"source"`
	Advisories  int       `json:"advisories"`
	AgeDays     int       `json:"age_days"`
	Stale       bool      `json:"stale"`
	Error       string    `json:"error"`
}

type advisoryMatch struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Score      float64  `json:"score"`
	CVEs       []string `json:"cves"`
	Product    string   `json:"product"`
	Affected   string   `json:"affected"`
	Confidence string   `json:"confidence"`
}

// snapshot is everything fetched so far. Each refresh replaces only the
// parts the open view needs.
type snapshot struct {
	Version    version
	Session    session
	Summary    *summary
	Devices    []models.DeviceInfo
	Alerts     []models.AlertEvent
	Anomalies  *models.AnomalySnapshot
	Assets     []asset
	Baseline   *baseline
	Zones      *zones
	Policy     *policy
	Captures   *captures
	Advisories *advisoryStatus
}

// needs lists the endpoints each view reads, so a refresh asks only for
// what is on screen.
var needs = map[view][]string{
	viewOverview:  {"summary", "alerts", "anomalies", "policy", "baseline", "captures", "advisories"},
	viewDevices:   {"devices", "assets"},
	viewAlerts:    {"alerts"},
	viewAnomalies: {"anomalies"},
	viewAssets:    {"assets", "advisories"},
	viewZones:     {"zones"},
	viewBaseline:  {"baseline"},
	viewPolicy:    {"policy"},
	viewCaptures:  {"captures"},
	viewDNS:       {"summary"},
}

// fetch fills a copy of prev with fresh data for v. The session is always
// refreshed, so the header shows the current role. A failing endpoint
// keeps its old data; the first error is returned for the status line.
func fetch(ctx context.Context, c *Client, prev snapshot, v view) (snapshot, error) {
	s := prev
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	keep(c.get(ctx, "/api/v1/session", &s.Session))
	if s.Version.Commit == "" {
		keep(c.get(ctx, "/api/v1/version", &s.Version))
	}
	// The summary and anomaly score are small and feed the charts, so they
	// are read on every refresh whatever the view.
	seen := map[string]bool{}
	for _, n := range append([]string{"summary", "anomalies"}, needs[v]...) {
		if seen[n] {
			continue
		}
		seen[n] = true
		switch n {
		case "summary":
			var x summary
			if err := c.get(ctx, "/api/v1/summary", &x); err == nil {
				s.Summary = &x
			} else {
				keep(err)
			}
		case "devices":
			var x []models.DeviceInfo
			if err := c.get(ctx, "/api/v1/devices", &x); err == nil {
				s.Devices = x
			} else {
				keep(err)
			}
		case "alerts":
			var x []models.AlertEvent
			if err := c.get(ctx, "/api/v1/alerts", &x); err == nil {
				s.Alerts = x
			} else {
				keep(err)
			}
		case "anomalies":
			var x models.AnomalySnapshot
			if err := c.get(ctx, "/api/v1/anomalies", &x); err == nil {
				s.Anomalies = &x
			} else {
				keep(err)
			}
		case "assets":
			var x []asset
			if err := c.get(ctx, "/api/v1/assets", &x); err == nil {
				s.Assets = x
			} else {
				keep(err)
			}
		case "baseline":
			var x baseline
			if err := c.get(ctx, "/api/v1/baseline?limit=2000", &x); err == nil {
				s.Baseline = &x
			} else {
				keep(err)
			}
		case "zones":
			var x zones
			if err := c.get(ctx, "/api/v1/zones", &x); err == nil {
				s.Zones = &x
			} else {
				keep(err)
			}
		case "policy":
			var x policy
			if err := c.get(ctx, "/api/v1/policy", &x); err == nil {
				s.Policy = &x
			} else if !isNotFound(err) { // no policy engine on this sensor
				keep(err)
			}
		case "captures":
			var x captures
			if err := c.get(ctx, "/api/v1/captures", &x); err == nil {
				s.Captures = &x
			} else if !isNotFound(err) {
				keep(err)
			}
		case "advisories":
			var x advisoryStatus
			if err := c.get(ctx, "/api/v1/advisories", &x); err == nil {
				s.Advisories = &x
			} else if !isNotFound(err) {
				keep(err)
			}
		}
	}
	return s, first
}

func isNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == 404
}

// deviceAdvisories reads the advisories matching one device.
func deviceAdvisories(ctx context.Context, c *Client, mac string) ([]advisoryMatch, error) {
	var out []advisoryMatch
	err := c.get(ctx, "/api/v1/assets/"+url.PathEscape(mac)+"/advisories", &out)
	if isNotFound(err) {
		return nil, nil
	}
	return out, err
}

// ackAlert acknowledges an alert with an optional note.
func ackAlert(ctx context.Context, c *Client, id, note string) error {
	return c.post(ctx, "/api/v1/alerts/"+url.PathEscape(id)+"/ack", map[string]string{"note": note}, nil)
}

// baselineAction approves or forgets flows ("approve" or "forget").
func baselineAction(ctx context.Context, c *Client, action string, ids []string) error {
	return c.post(ctx, "/api/v1/baseline/"+action, map[string][]string{"ids": ids}, nil)
}
