package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/version"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	monitor *monitor.NetworkMonitor
}

func NewServer(mon *monitor.NetworkMonitor) *Server {
	return &Server{monitor: mon}
}

func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/summary", s.handleSummary)
	mux.HandleFunc("/api/v1/devices", s.handleDevices)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/anomalies", s.handleAnomalies)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/metrics", s.handleMetrics)

	staticSub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	mux.Handle("/", http.FileServer(http.FS(staticSub)))

	return mux, nil
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
	DNSCorrelated    map[string]int      `json:"dns_correlated_domains"`
	RecentDevice     []deviceSummaryItem `json:"recent_devices"`
}

type deviceSummaryItem struct {
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	Vendor       string    `json:"vendor"`
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
		for domain, count := range d.CorrelatedDomains {
			dnsCorrelated[domain] += count
		}
		topVendors[d.Vendor]++
		deviceItems = append(deviceItems, deviceSummaryItem{
			MAC:          d.MAC,
			IP:           d.IP,
			Vendor:       d.Vendor,
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
