package alerts

import (
	"fmt"

	"github.com/zrougamed/cerberus/internal/models"
)

// MetricValue returns the numeric value for a known metric on a device.
func MetricValue(device *models.DeviceInfo, metric string) (float64, bool) {
	if device == nil {
		return 0, false
	}
	switch metric {
	case MetricDNSQueries:
		return float64(device.DNSQueries), true
	case MetricTCPConnections:
		return float64(device.TCPConnections), true
	case MetricUDPConnections:
		return float64(device.UDPConnections), true
	case MetricUniqueTargets:
		return float64(len(device.Targets)), true
	case MetricICMPPackets:
		return float64(device.ICMPPackets), true
	case MetricHTTPRequests:
		return float64(device.HTTPRequests), true
	case MetricTLSConnections:
		return float64(device.TLSConnections), true
	case MetricDNSCorrelated:
		return float64(device.DNSCorrelated), true
	default:
		return 0, false
	}
}

// Compare applies op to observed vs threshold value.
func Compare(op string, observed, threshold float64) bool {
	switch op {
	case OpGT:
		return observed > threshold
	case OpGTE:
		return observed >= threshold
	case OpLT:
		return observed < threshold
	case OpLTE:
		return observed <= threshold
	case OpEQ:
		return observed == threshold
	default:
		return false
	}
}

// EvalResult is the outcome of evaluating one threshold rule against a device.
type EvalResult struct {
	Rule      ThresholdRule
	Triggered bool
	Observed  float64
	Message   string
}

// EvaluateThresholds runs all enabled threshold rules against the device.
// Disabled rules are skipped. Unknown metrics (should not happen after Validate) are skipped.
func EvaluateThresholds(cfg Config, device *models.DeviceInfo) []EvalResult {
	out := make([]EvalResult, 0, len(cfg.Thresholds))
	for _, rule := range cfg.Thresholds {
		if !rule.Enabled {
			continue
		}
		observed, ok := MetricValue(device, rule.Metric)
		if !ok {
			continue
		}
		triggered := Compare(rule.Op, observed, rule.Value)
		msg := rule.Message
		if msg == "" {
			msg = fmt.Sprintf("%s %s %.0f", rule.Metric, rule.Op, rule.Value)
		}
		if triggered {
			msg = fmt.Sprintf("%s (%s %.0f %s %.0f)", msg, rule.Metric, observed, rule.Op, rule.Value)
		}
		out = append(out, EvalResult{
			Rule:      rule,
			Triggered: triggered,
			Observed:  observed,
			Message:   msg,
		})
	}
	return out
}
