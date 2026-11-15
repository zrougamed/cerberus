package api

import (
	"cmp"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zrougamed/cerberus/internal/capture"
	"github.com/zrougamed/cerberus/internal/kstats"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/policy"
	"github.com/zrougamed/cerberus/internal/version"
)

//go:embed all:web
var webFS embed.FS

type Server struct {
	monitor *monitor.NetworkMonitor
	// Set once the BPF collection is loaded, which happens after the HTTP
	// server has started, hence atomic.
	kernelStats atomic.Pointer[kernelStatsFunc]

	policy *policy.Engine
	// Set after the capture interfaces are known, which is after the HTTP
	// server starts, hence atomic. Nil when capture is disabled.
	capture   atomic.Pointer[capture.Capturer]
	tokenHash []byte // sha256 of CERBERUS_API_TOKEN; nil disables writes
	authLimit authLimiter
}

type kernelStatsFunc func() (kstats.Snapshot, error)

func NewServer(mon *monitor.NetworkMonitor) *Server {
	return &Server{monitor: mon}
}

// SetKernelStats registers the source of the BPF-side counters exported in
// /metrics. Without it those series are omitted.
func (s *Server) SetKernelStats(fn func() (kstats.Snapshot, error)) {
	f := kernelStatsFunc(fn)
	s.kernelStats.Store(&f)
}

func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/summary", s.handleSummary)
	mux.HandleFunc("/api/v1/devices", s.handleDevices)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/anomalies", s.handleAnomalies)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/metrics", s.handleMetrics)
	s.registerDocsRoutes(mux)
	s.registerAssetRoutes(mux)
	s.registerBaselineRoutes(mux)
	s.registerCaptureRoutes(mux)
	s.registerSegmentationRoutes(mux)
	mux.HandleFunc("GET /api/v1/zones", s.handleZones)
	if s.policy != nil {
		s.registerPolicyRoutes(mux)
	}

	staticSub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	mux.Handle("/", http.FileServer(http.FS(staticSub)))

	return securityHeaders(mux), nil
}

// contentSecurityPolicy allows only the embedded dashboard's own script and
// stylesheet, Google Fonts, and same-origin API calls. There is no inline
// script or style in internal/api/web; keep it that way (use classes in
// styles.css) or the browser will block it.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self' https://fonts.googleapis.com; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders sets browser hardening headers on every response. The
// dashboard is never meant to be framed, and the API carries the device
// inventory, so responses are not cached either.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		csp := contentSecurityPolicy
		if r.URL.Path == "/docs" || strings.HasPrefix(r.URL.Path, "/docs/") {
			csp = docsContentSecurityPolicy
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type summaryResponse struct {
	GeneratedAt      time.Time           `json:"generated_at"`
	PacketStats      map[string]uint64   `json:"packet_stats"`
	DeviceCount      int                 `json:"device_count"`
	TopServices      map[string]int      `json:"top_services"`
	TopVendors       map[string]int      `json:"top_vendors"`
	DNSQueryTypes    map[string]int      `json:"dns_query_types"`
	DNSResponseCodes map[string]int      `json:"dns_response_codes"`
	DNSResponseNames map[string]int      `json:"dns_response_domains"`
	EncryptedDNS     map[string]int      `json:"encrypted_dns"`
	TLSVersions      map[string]int      `json:"tls_versions"`
	TLSSNIs          map[string]int      `json:"top_tls_snis"`
	DNSCorrelated    map[string]int      `json:"dns_correlated_domains"`
	RecentDevice     []deviceSummaryItem `json:"recent_devices"`
}

type deviceSummaryItem struct {
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	Vendor       string    `json:"vendor"`
	IsGateway    bool      `json:"is_gateway,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	TCP          int       `json:"tcp"`
	UDP          int       `json:"udp"`
	DNSQueries   int       `json:"dns_queries"`
	HTTPRequests int       `json:"http_requests"`
	TLS          int       `json:"tls"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	devices := s.monitor.GetStats()
	packetStats := s.monitor.SnapshotPacketStats()

	topServices := make(map[string]int)
	topVendors := make(map[string]int)
	dnsQueryTypes := make(map[string]int)
	dnsResponseCodes := make(map[string]int)
	dnsResponseNames := make(map[string]int)
	encryptedDNS := make(map[string]int)
	tlsVersions := make(map[string]int)
	tlsSNIs := make(map[string]int)
	dnsCorrelated := make(map[string]int)
	deviceItems := make([]deviceSummaryItem, 0, len(devices))

	for _, d := range devices {
		for svc, count := range d.Services {
			topServices[svc] += count
		}
		for qtype, count := range d.DNSQueryTypes {
			dnsQueryTypes[qtype] += count
		}
		for rcode, count := range d.DNSResponseCodes {
			dnsResponseCodes[rcode] += count
		}
		for domain, count := range d.DNSResponseDomains {
			dnsResponseNames[domain] += count
		}
		for mode, count := range d.EncryptedDNS {
			encryptedDNS[mode] += count
		}
		for version, count := range d.TLSVersions {
			tlsVersions[version] += count
		}
		for sni, count := range d.TLSSNIs {
			tlsSNIs[sni] += count
		}
		for domain, count := range d.CorrelatedDomains {
			dnsCorrelated[domain] += count
		}
		topVendors[d.Vendor]++
		deviceItems = append(deviceItems, deviceSummaryItem{
			MAC:          d.MAC,
			IP:           d.IP,
			Vendor:       d.Vendor,
			IsGateway:    d.IsGateway,
			FirstSeen:    d.FirstSeen,
			LastSeen:     d.LastSeen,
			TCP:          d.TCPConnections,
			UDP:          d.UDPConnections,
			DNSQueries:   d.DNSQueries,
			HTTPRequests: d.HTTPRequests,
			TLS:          d.TLSConnections,
		})
	}

	sort.Slice(deviceItems, func(i, j int) bool {
		return deviceItems[i].LastSeen.After(deviceItems[j].LastSeen)
	})
	if len(deviceItems) > 8 {
		deviceItems = deviceItems[:8]
	}

	writeJSON(w, http.StatusOK, summaryResponse{
		GeneratedAt:      time.Now(),
		PacketStats:      packetStats,
		DeviceCount:      len(devices),
		TopServices:      topMap(topServices, 8),
		TopVendors:       topMap(topVendors, 8),
		DNSQueryTypes:    topMap(dnsQueryTypes, 8),
		DNSResponseCodes: topMap(dnsResponseCodes, 8),
		DNSResponseNames: topMap(dnsResponseNames, 8),
		EncryptedDNS:     topMap(encryptedDNS, 8),
		TLSVersions:      topMap(tlsVersions, 8),
		TLSSNIs:          topMap(tlsSNIs, 8),
		DNSCorrelated:    topMap(dnsCorrelated, 8),
		RecentDevice:     deviceItems,
	})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	devices := s.monitor.GetStats()
	out := make([]*models.DeviceInfo, 0, len(devices))
	for _, d := range devices {
		out = append(out, d)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	writeJSON(w, http.StatusOK, out)
}

// handleZones returns the configured zones (with device counts), conduits
// and violation counters.
func (s *Server) handleZones(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.monitor.GetZoneSummary())
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	alerts := s.monitor.GetAlerts()
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].ObservedAt.After(alerts[j].ObservedAt)
	})
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.GetAnomalySnapshot())
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, version.Get())
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	devices := s.monitor.GetStats()
	pkt := s.monitor.SnapshotPacketStats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	v := version.Get()
	fmt.Fprintln(w, "# HELP cerberus_build_info Build metadata (commit, build date). Always 1.")
	fmt.Fprintln(w, "# TYPE cerberus_build_info gauge")
	fmt.Fprintf(w, "cerberus_build_info{commit=\"%s\",date=\"%s\"} 1\n\n", escapeLabelValue(v.Commit), escapeLabelValue(v.Date))

	fmt.Fprintln(w, "# HELP cerberus_packets_total Total observed packets by protocol.")
	fmt.Fprintln(w, "# TYPE cerberus_packets_total counter")
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"total\"} %d\n", pkt["total"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"arp\"} %d\n", pkt["arp"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"tcp\"} %d\n", pkt["tcp"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"udp\"} %d\n", pkt["udp"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"icmp\"} %d\n", pkt["icmp"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"dns\"} %d\n", pkt["dns"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"http\"} %d\n", pkt["http"])
	fmt.Fprintf(w, "cerberus_packets_total{protocol=\"tls\"} %d\n", pkt["tls"])
	fmt.Fprintln(w)

	s.writeKernelMetrics(w)

	if hits := s.monitor.GetWatchlistHits(); len(hits) > 0 {
		ids := slices.Sorted(maps.Keys(hits))
		fmt.Fprintln(w, "# HELP cerberus_watchlist_hits_total Packets to or from an address on a watchlist.")
		fmt.Fprintln(w, "# TYPE cerberus_watchlist_hits_total counter")
		for _, id := range ids {
			fmt.Fprintf(w, "cerberus_watchlist_hits_total{list=\"%s\"} %d\n", escapeLabelValue(id), hits[id])
		}
		fmt.Fprintln(w)
	}

	if counts := s.monitor.GetIndustrialCounts(); len(counts) > 0 {
		keys := slices.SortedFunc(maps.Keys(counts), func(a, b monitor.IndustrialCountKey) int {
			return cmp.Or(cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.Class, b.Class), cmpBool(a.Response, b.Response))
		})
		fmt.Fprintln(w, "# HELP cerberus_industrial_messages_total Decoded industrial protocol messages by operation class and direction.")
		fmt.Fprintln(w, "# TYPE cerberus_industrial_messages_total counter")
		for _, k := range keys {
			direction := "request"
			if k.Response {
				direction = "response"
			}
			fmt.Fprintf(w, "cerberus_industrial_messages_total{protocol=\"%s\",class=\"%s\",direction=\"%s\"} %d\n",
				escapeLabelValue(k.Protocol), escapeLabelValue(k.Class), direction, counts[k])
		}
		fmt.Fprintln(w)
	}

	if bs := s.monitor.GetBaselineStatus(); bs.State != monitor.BaselineDisabled {
		fmt.Fprintln(w, "# HELP cerberus_baseline_flows Industrial flows in the baseline by status.")
		fmt.Fprintln(w, "# TYPE cerberus_baseline_flows gauge")
		fmt.Fprintf(w, "cerberus_baseline_flows{status=\"learned\"} %d\n", bs.Learned)
		fmt.Fprintf(w, "cerberus_baseline_flows{status=\"approved\"} %d\n", bs.Approved)
		fmt.Fprintf(w, "cerberus_baseline_flows{status=\"new\"} %d\n", bs.New)
		fmt.Fprintln(w, "# HELP cerberus_baseline_dropped_total Flows not recorded because the baseline was full.")
		fmt.Fprintln(w, "# TYPE cerberus_baseline_dropped_total counter")
		fmt.Fprintf(w, "cerberus_baseline_dropped_total %d\n", bs.Dropped)
		learning := 0
		if bs.State == monitor.BaselineLearning {
			learning = 1
		}
		fmt.Fprintln(w, "# HELP cerberus_baseline_learning 1 while the flow baseline is still learning.")
		fmt.Fprintln(w, "# TYPE cerberus_baseline_learning gauge")
		fmt.Fprintf(w, "cerberus_baseline_learning %d\n\n", learning)
	}

	if zs := s.monitor.GetZoneSummary(); len(zs.Violations) > 0 {
		fmt.Fprintln(w, "# HELP cerberus_zone_violations_total Packets between zones that no conduit allows.")
		fmt.Fprintln(w, "# TYPE cerberus_zone_violations_total counter")
		for _, k := range slices.Sorted(maps.Keys(zs.Violations)) {
			from, to, _ := strings.Cut(k, ">")
			fmt.Fprintf(w, "cerberus_zone_violations_total{from=\"%s\",to=\"%s\"} %d\n", escapeLabelValue(from), escapeLabelValue(to), zs.Violations[k])
		}
		fmt.Fprintln(w)
	}

	if c := s.capture.Load(); c != nil {
		cs := c.Status()
		fmt.Fprintln(w, "# HELP cerberus_capture_buffer_packets Frames held in the capture ring.")
		fmt.Fprintln(w, "# TYPE cerberus_capture_buffer_packets gauge")
		fmt.Fprintf(w, "cerberus_capture_buffer_packets %d\n", cs.BufferPackets)
		fmt.Fprintln(w, "# HELP cerberus_capture_buffer_bytes Bytes held in the capture ring.")
		fmt.Fprintln(w, "# TYPE cerberus_capture_buffer_bytes gauge")
		fmt.Fprintf(w, "cerberus_capture_buffer_bytes %d\n", cs.BufferBytes)
		fmt.Fprintln(w, "# HELP cerberus_capture_kernel_drops_total Frames the kernel dropped because the capture reader fell behind.")
		fmt.Fprintln(w, "# TYPE cerberus_capture_kernel_drops_total counter")
		fmt.Fprintf(w, "cerberus_capture_kernel_drops_total %d\n", cs.KernelDrops)
		fmt.Fprintln(w, "# HELP cerberus_capture_skipped_total Alert captures skipped by the rate limit or a full queue.")
		fmt.Fprintln(w, "# TYPE cerberus_capture_skipped_total counter")
		fmt.Fprintf(w, "cerberus_capture_skipped_total %d\n\n", cs.Skipped)
	}

	fmt.Fprintln(w, "# HELP cerberus_devices_total Number of tracked devices.")
	fmt.Fprintln(w, "# TYPE cerberus_devices_total gauge")
	fmt.Fprintf(w, "cerberus_devices_total %d\n\n", len(devices))

	fmt.Fprintln(w, "# HELP cerberus_device_protocol_events_total Per-device protocol event counters.")
	fmt.Fprintln(w, "# TYPE cerberus_device_protocol_events_total counter")
	for _, d := range devices {
		mac := escapeLabelValue(d.MAC)
		vendor := escapeLabelValue(d.Vendor)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"dns\"} %d\n", mac, vendor, d.DNSQueries)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"http\"} %d\n", mac, vendor, d.HTTPRequests)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"tls\"} %d\n", mac, vendor, d.TLSConnections)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"tcp\"} %d\n", mac, vendor, d.TCPConnections)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"udp\"} %d\n", mac, vendor, d.UDPConnections)
		fmt.Fprintf(w, "cerberus_device_protocol_events_total{mac=\"%s\",vendor=\"%s\",protocol=\"icmp\"} %d\n", mac, vendor, d.ICMPPackets)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP cerberus_tls_versions_total TLS versions observed across devices.")
	fmt.Fprintln(w, "# TYPE cerberus_tls_versions_total counter")
	for _, d := range devices {
		for version, count := range d.TLSVersions {
			fmt.Fprintf(w, "cerberus_tls_versions_total{version=\"%s\"} %d\n", escapeLabelValue(version), count)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP cerberus_encrypted_dns_total Encrypted DNS sessions identified by mode.")
	fmt.Fprintln(w, "# TYPE cerberus_encrypted_dns_total counter")
	for _, d := range devices {
		for mode, count := range d.EncryptedDNS {
			fmt.Fprintf(w, "cerberus_encrypted_dns_total{mac=\"%s\",mode=\"%s\"} %d\n", escapeLabelValue(d.MAC), escapeLabelValue(mode), count)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP cerberus_dns_correlated_connections_total Connections correlated to recent DNS queries.")
	fmt.Fprintln(w, "# TYPE cerberus_dns_correlated_connections_total counter")
	for _, d := range devices {
		fmt.Fprintf(w, "cerberus_dns_correlated_connections_total{mac=\"%s\"} %d\n", escapeLabelValue(d.MAC), d.DNSCorrelated)
		for domain, count := range d.CorrelatedDomains {
			fmt.Fprintf(w, "cerberus_dns_correlated_connections_total{mac=\"%s\",domain=\"%s\"} %d\n", escapeLabelValue(d.MAC), escapeLabelValue(domain), count)
		}
	}
}

// writeKernelMetrics exports the classifier's own counters. They count every
// packet the hook saw, including ones that produced no event, and the events
// lost to a full ring buffer.
func (s *Server) writeKernelMetrics(w io.Writer) {
	fn := s.kernelStats.Load()
	if fn == nil {
		return
	}
	snap, err := (*fn)()
	if err != nil {
		fmt.Fprintf(w, "# kernel counters unavailable: %s\n\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	classes := []struct {
		name string
		c    kstats.Counter
	}{
		{"total", snap.Total},
		{"arp", snap.ARP},
		{"ipv4", snap.IPv4},
		{"ipv6", snap.IPv6},
		{"other", snap.Other},
	}
	fmt.Fprintln(w, "# HELP cerberus_kernel_packets_total Packets seen by the TC hook, by L3 class.")
	fmt.Fprintln(w, "# TYPE cerberus_kernel_packets_total counter")
	for _, c := range classes {
		fmt.Fprintf(w, "cerberus_kernel_packets_total{class=\"%s\"} %d\n", c.name, c.c.Packets)
	}
	fmt.Fprintln(w, "# HELP cerberus_kernel_bytes_total Bytes seen by the TC hook, by L3 class.")
	fmt.Fprintln(w, "# TYPE cerberus_kernel_bytes_total counter")
	for _, c := range classes {
		fmt.Fprintf(w, "cerberus_kernel_bytes_total{class=\"%s\"} %d\n", c.name, c.c.Bytes)
	}
	fmt.Fprintln(w, "# HELP cerberus_ringbuf_dropped_events_total Events lost because the ring buffer was full.")
	fmt.Fprintln(w, "# TYPE cerberus_ringbuf_dropped_events_total counter")
	fmt.Fprintf(w, "cerberus_ringbuf_dropped_events_total %d\n", snap.RingbufFull.Packets)
	fmt.Fprintln(w, "# HELP cerberus_policy_dropped_packets_total Packets dropped by enforced policy rules.")
	fmt.Fprintln(w, "# TYPE cerberus_policy_dropped_packets_total counter")
	fmt.Fprintf(w, "cerberus_policy_dropped_packets_total %d\n", snap.PolicyDropped.Packets)
	fmt.Fprintln(w, "# HELP cerberus_filter_log_lost_total Filter log events lost because the log ring buffer was full.")
	fmt.Fprintln(w, "# TYPE cerberus_filter_log_lost_total counter")
	fmt.Fprintf(w, "cerberus_filter_log_lost_total %d\n\n", snap.FilterLogLost.Packets)
}

func escapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}

func topMap(values map[string]int, limit int) map[string]int {
	type pair struct {
		key   string
		value int
	}
	items := make([]pair, 0, len(values))
	for k, v := range values {
		items = append(items, pair{key: k, value: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].value > items[j].value
	})
	if len(items) > limit {
		items = items[:limit]
	}
	result := make(map[string]int, len(items))
	for _, item := range items {
		result[item.key] = item.value
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// cmpBool orders false before true.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}
