package alerts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Supported threshold metrics (device-scoped counters / derived values).
const (
	MetricDNSQueries     = "dns_queries"
	MetricTCPConnections = "tcp_connections"
	MetricUDPConnections = "udp_connections"
	MetricUniqueTargets  = "unique_targets"
	MetricICMPPackets    = "icmp_packets"
	MetricHTTPRequests   = "http_requests"
	MetricTLSConnections = "tls_connections"
	MetricDNSCorrelated  = "dns_correlated"
)

// Supported comparison operators.
const (
	OpGT  = "gt"
	OpGTE = "gte"
	OpLT  = "lt"
	OpLTE = "lte"
	OpEQ  = "eq"
)

// Config is the declarative alerting configuration.
// Threshold rules, security baselines, and anomaly detector settings are typed
// kinds validated at load time (fail-closed on invalid config).
type Config struct {
	// TargetHistorySize caps the rolling unique-destination list per device.
	// Threshold unique_targets must stay below this or target_spread never fires.
	TargetHistorySize int             `yaml:"target_history_size" json:"target_history_size"`
	Thresholds        []ThresholdRule `yaml:"thresholds" json:"thresholds"`
	Baselines         BaselineConfig  `yaml:"baselines" json:"baselines"`
	Anomaly           AnomalyConfig   `yaml:"anomaly" json:"anomaly"`
}

// ThresholdRule is a declarative comparison against a device metric.
type ThresholdRule struct {
	ID       string  `yaml:"id" json:"id"`
	Enabled  bool    `yaml:"enabled" json:"enabled"`
	Metric   string  `yaml:"metric" json:"metric"`
	Op       string  `yaml:"op" json:"op"`
	Value    float64 `yaml:"value" json:"value"`
	Severity string  `yaml:"severity" json:"severity"`
	Message  string  `yaml:"message" json:"message"`
}

// BaselineRule configures a first-seen / known-good security baseline alert.
type BaselineRule struct {
	Enabled   bool     `yaml:"enabled" json:"enabled"`
	KnownGood []string `yaml:"known_good" json:"known_good"`
}

// BaselineConfig holds the three built-in security baseline rules.
type BaselineConfig struct {
	RogueDHCPServer   BaselineRule `yaml:"rogue_dhcp_server" json:"rogue_dhcp_server"`
	RogueIPv6RASource BaselineRule `yaml:"rogue_ipv6_ra_source" json:"rogue_ipv6_ra_source"`
	GatewayMACChanged BaselineRule `yaml:"gateway_mac_changed" json:"gateway_mac_changed"`
}

// AnomalyConfig tunes the ML-lite windowed anomaly detector.
type AnomalyConfig struct {
	Enabled         bool    `yaml:"enabled" json:"enabled"`
	WindowSeconds   int     `yaml:"window_seconds" json:"window_seconds"`
	BaselineWindows int     `yaml:"baseline_windows" json:"baseline_windows"`
	ScoreThreshold  float64 `yaml:"score_threshold" json:"score_threshold"`
	MaxHistory      int     `yaml:"max_history" json:"max_history"`
	MaxAlerts       int     `yaml:"max_alerts" json:"max_alerts"`
}

// fileOverlay is used so omitted sections keep DefaultConfig values.
type fileOverlay struct {
	TargetHistorySize *int                `yaml:"target_history_size" json:"target_history_size"`
	Thresholds        *[]thresholdOverlay `yaml:"thresholds" json:"thresholds"`
	Baselines         *baselineOverlay    `yaml:"baselines" json:"baselines"`
	Anomaly           *anomalyOverlay     `yaml:"anomaly" json:"anomaly"`
}

type thresholdOverlay struct {
	ID       string   `yaml:"id" json:"id"`
	Enabled  *bool    `yaml:"enabled" json:"enabled"`
	Metric   *string  `yaml:"metric" json:"metric"`
	Op       *string  `yaml:"op" json:"op"`
	Value    *float64 `yaml:"value" json:"value"`
	Severity *string  `yaml:"severity" json:"severity"`
	Message  *string  `yaml:"message" json:"message"`
}

type baselineRuleOverlay struct {
	Enabled   *bool    `yaml:"enabled" json:"enabled"`
	KnownGood []string `yaml:"known_good" json:"known_good"`
}

type baselineOverlay struct {
	RogueDHCPServer   *baselineRuleOverlay `yaml:"rogue_dhcp_server" json:"rogue_dhcp_server"`
	RogueIPv6RASource *baselineRuleOverlay `yaml:"rogue_ipv6_ra_source" json:"rogue_ipv6_ra_source"`
	GatewayMACChanged *baselineRuleOverlay `yaml:"gateway_mac_changed" json:"gateway_mac_changed"`
}

type anomalyOverlay struct {
	Enabled         *bool    `yaml:"enabled" json:"enabled"`
	WindowSeconds   *int     `yaml:"window_seconds" json:"window_seconds"`
	BaselineWindows *int     `yaml:"baseline_windows" json:"baseline_windows"`
	ScoreThreshold  *float64 `yaml:"score_threshold" json:"score_threshold"`
	MaxHistory      *int     `yaml:"max_history" json:"max_history"`
	MaxAlerts       *int     `yaml:"max_alerts" json:"max_alerts"`
}

// DefaultConfig returns the built-in alerting policy (matches former hardcoded values).
func DefaultConfig() Config {
	return Config{
		TargetHistorySize: 20,
		Thresholds: []ThresholdRule{
			{
				ID:       "dns_query_volume",
				Enabled:  true,
				Metric:   MetricDNSQueries,
				Op:       OpGT,
				Value:    200,
				Severity: "high",
				Message:  "DNS queries exceeded threshold",
			},
			{
				ID:       "tcp_connection_volume",
				Enabled:  true,
				Metric:   MetricTCPConnections,
				Op:       OpGT,
				Value:    500,
				Severity: "high",
				Message:  "TCP connections exceeded threshold",
			},
			{
				ID:       "target_spread",
				Enabled:  true,
				Metric:   MetricUniqueTargets,
				Op:       OpGT,
				Value:    18,
				Severity: "medium",
				Message:  "Unique targets exceeded threshold",
			},
		},
		Baselines: BaselineConfig{
			RogueDHCPServer:   BaselineRule{Enabled: true},
			RogueIPv6RASource: BaselineRule{Enabled: true},
			GatewayMACChanged: BaselineRule{Enabled: true},
		},
		Anomaly: AnomalyConfig{
			Enabled:         true,
			WindowSeconds:   30,
			BaselineWindows: 20,
			ScoreThreshold:  3.5,
			MaxHistory:      120,
			MaxAlerts:       100,
		},
	}
}

// LoadFile reads a YAML or JSON alerts config and merges it onto DefaultConfig.
// Omitted sections keep defaults; invalid configs return an error (fail-closed).
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read alerts config: %w", err)
	}
	return Parse(data, filepath.Ext(path))
}

// Parse merges overlay bytes onto defaults. ext selects YAML (.yaml/.yml) or JSON (.json).
// Empty ext defaults to YAML.
func Parse(data []byte, ext string) (Config, error) {
	cfg := DefaultConfig()
	var overlay fileOverlay
	ext = strings.ToLower(ext)
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &overlay); err != nil {
			return Config{}, fmt.Errorf("parse alerts config JSON: %w", err)
		}
	case ".yaml", ".yml", "":
		if err := yaml.Unmarshal(data, &overlay); err != nil {
			return Config{}, fmt.Errorf("parse alerts config YAML: %w", err)
		}
	default:
		return Config{}, fmt.Errorf("unsupported alerts config extension %q (use .yaml, .yml, or .json)", ext)
	}
	if err := mergeOverlay(&cfg, overlay); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func mergeOverlay(cfg *Config, o fileOverlay) error {
	if o.TargetHistorySize != nil {
		cfg.TargetHistorySize = *o.TargetHistorySize
	}
	if o.Thresholds != nil {
		for _, t := range *o.Thresholds {
			if strings.TrimSpace(t.ID) == "" {
				return fmt.Errorf("threshold rule missing id")
			}
			idx := indexThreshold(cfg.Thresholds, t.ID)
			if idx < 0 {
				rule := ThresholdRule{ID: t.ID, Enabled: true, Op: OpGT, Severity: "medium"}
				applyThresholdOverlay(&rule, t)
				cfg.Thresholds = append(cfg.Thresholds, rule)
				continue
			}
			applyThresholdOverlay(&cfg.Thresholds[idx], t)
		}
	}
	if o.Baselines != nil {
		mergeBaselineRule(&cfg.Baselines.RogueDHCPServer, o.Baselines.RogueDHCPServer)
		mergeBaselineRule(&cfg.Baselines.RogueIPv6RASource, o.Baselines.RogueIPv6RASource)
		mergeBaselineRule(&cfg.Baselines.GatewayMACChanged, o.Baselines.GatewayMACChanged)
	}
	if o.Anomaly != nil {
		a := o.Anomaly
		if a.Enabled != nil {
			cfg.Anomaly.Enabled = *a.Enabled
		}
		if a.WindowSeconds != nil {
			cfg.Anomaly.WindowSeconds = *a.WindowSeconds
		}
		if a.BaselineWindows != nil {
			cfg.Anomaly.BaselineWindows = *a.BaselineWindows
		}
		if a.ScoreThreshold != nil {
			cfg.Anomaly.ScoreThreshold = *a.ScoreThreshold
		}
		if a.MaxHistory != nil {
			cfg.Anomaly.MaxHistory = *a.MaxHistory
		}
		if a.MaxAlerts != nil {
			cfg.Anomaly.MaxAlerts = *a.MaxAlerts
		}
	}
	return nil
}

func indexThreshold(rules []ThresholdRule, id string) int {
	for i := range rules {
		if rules[i].ID == id {
			return i
		}
	}
	return -1
}

func applyThresholdOverlay(dst *ThresholdRule, src thresholdOverlay) {
	if src.Enabled != nil {
		dst.Enabled = *src.Enabled
	}
	if src.Metric != nil {
		dst.Metric = *src.Metric
	}
	if src.Op != nil {
		dst.Op = *src.Op
	}
	if src.Value != nil {
		dst.Value = *src.Value
	}
	if src.Severity != nil {
		dst.Severity = *src.Severity
	}
	if src.Message != nil {
		dst.Message = *src.Message
	}
}

func mergeBaselineRule(dst *BaselineRule, src *baselineRuleOverlay) {
	if src == nil {
		return
	}
	if src.Enabled != nil {
		dst.Enabled = *src.Enabled
	}
	if src.KnownGood != nil {
		dst.KnownGood = append([]string(nil), src.KnownGood...)
	}
}

// Validate checks the config for structural errors. Call after Parse/DefaultConfig.
func (c Config) Validate() error {
	if c.TargetHistorySize < 1 {
		return fmt.Errorf("target_history_size must be >= 1")
	}
	seen := make(map[string]struct{}, len(c.Thresholds))
	for i, r := range c.Thresholds {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("thresholds[%d]: id is required", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("thresholds: duplicate id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if !r.Enabled {
			continue
		}
		if !validMetric(r.Metric) {
			return fmt.Errorf("threshold %q: unknown metric %q", r.ID, r.Metric)
		}
		if !validOp(r.Op) {
			return fmt.Errorf("threshold %q: unknown op %q (want gt|gte|lt|lte|eq)", r.ID, r.Op)
		}
		if !validSeverity(r.Severity) {
			return fmt.Errorf("threshold %q: unknown severity %q (want low|medium|high)", r.ID, r.Severity)
		}
		if r.Metric == MetricUniqueTargets && r.Value >= float64(c.TargetHistorySize) {
			return fmt.Errorf("threshold %q: value %.0f must be < target_history_size (%d) or it never fires",
				r.ID, r.Value, c.TargetHistorySize)
		}
	}
	if c.Anomaly.Enabled {
		if c.Anomaly.WindowSeconds < 1 {
			return fmt.Errorf("anomaly.window_seconds must be >= 1")
		}
		if c.Anomaly.BaselineWindows < 1 {
			return fmt.Errorf("anomaly.baseline_windows must be >= 1")
		}
		if c.Anomaly.ScoreThreshold <= 0 {
			return fmt.Errorf("anomaly.score_threshold must be > 0")
		}
		if c.Anomaly.MaxHistory < 1 {
			return fmt.Errorf("anomaly.max_history must be >= 1")
		}
		if c.Anomaly.MaxAlerts < 1 {
			return fmt.Errorf("anomaly.max_alerts must be >= 1")
		}
	}
	return nil
}

func validMetric(m string) bool {
	switch m {
	case MetricDNSQueries, MetricTCPConnections, MetricUDPConnections, MetricUniqueTargets,
		MetricICMPPackets, MetricHTTPRequests, MetricTLSConnections, MetricDNSCorrelated:
		return true
	default:
		return false
	}
}

func validOp(op string) bool {
	switch op {
	case OpGT, OpGTE, OpLT, OpLTE, OpEQ:
		return true
	default:
		return false
	}
}

func validSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "low", "medium", "high":
		return true
	default:
		return false
	}
}

// KnownMetrics returns the catalog of threshold metrics for docs/tests.
func KnownMetrics() []string {
	return []string{
		MetricDNSQueries,
		MetricTCPConnections,
		MetricUDPConnections,
		MetricUniqueTargets,
		MetricICMPPackets,
		MetricHTTPRequests,
		MetricTLSConnections,
		MetricDNSCorrelated,
	}
}
