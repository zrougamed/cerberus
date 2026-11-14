package alerts

import (
	"fmt"
	"net/netip"
)

// Rule ids raised by the industrial protocol decoders.
const (
	RuleModbusWrite      = "modbus_write"
	RuleModbusDiagnostic = "modbus_diagnostic"
)

// defaultIndustrialRealertSeconds keeps a polling SCADA master that writes
// every few seconds from producing more than one alert an hour per target.
const defaultIndustrialRealertSeconds = 3600

// IndustrialRule configures an alert raised from a decoded control-protocol
// operation.
type IndustrialRule struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Severity string `yaml:"severity" json:"severity"`
	// AllowedSources lists addresses or CIDRs (typically the SCADA server
	// and engineering workstations) whose operations are counted but never
	// alerted on.
	AllowedSources []string `yaml:"allowed_sources" json:"allowed_sources"`
	// RealertSeconds is the minimum gap between two alerts for the same
	// source, target and unit.
	RealertSeconds int `yaml:"realert_seconds" json:"realert_seconds"`
}

// IndustrialConfig holds the alert rules for industrial protocols.
type IndustrialConfig struct {
	ModbusWrite      IndustrialRule `yaml:"modbus_write" json:"modbus_write"`
	ModbusDiagnostic IndustrialRule `yaml:"modbus_diagnostic" json:"modbus_diagnostic"`
}

type industrialRuleOverlay struct {
	Enabled        *bool    `yaml:"enabled" json:"enabled"`
	Severity       *string  `yaml:"severity" json:"severity"`
	AllowedSources []string `yaml:"allowed_sources" json:"allowed_sources"`
	RealertSeconds *int     `yaml:"realert_seconds" json:"realert_seconds"`
}

type industrialOverlay struct {
	ModbusWrite      *industrialRuleOverlay `yaml:"modbus_write" json:"modbus_write"`
	ModbusDiagnostic *industrialRuleOverlay `yaml:"modbus_diagnostic" json:"modbus_diagnostic"`
}

func defaultIndustrialConfig() IndustrialConfig {
	return IndustrialConfig{
		ModbusWrite:      IndustrialRule{Enabled: true, Severity: "high", RealertSeconds: defaultIndustrialRealertSeconds},
		ModbusDiagnostic: IndustrialRule{Enabled: true, Severity: "high", RealertSeconds: defaultIndustrialRealertSeconds},
	}
}

func mergeIndustrial(dst *IndustrialConfig, src *industrialOverlay) {
	if src == nil {
		return
	}
	mergeIndustrialRule(&dst.ModbusWrite, src.ModbusWrite)
	mergeIndustrialRule(&dst.ModbusDiagnostic, src.ModbusDiagnostic)
}

func mergeIndustrialRule(dst *IndustrialRule, src *industrialRuleOverlay) {
	if src == nil {
		return
	}
	if src.Enabled != nil {
		dst.Enabled = *src.Enabled
	}
	if src.Severity != nil {
		dst.Severity = *src.Severity
	}
	if src.AllowedSources != nil {
		dst.AllowedSources = append([]string(nil), src.AllowedSources...)
	}
	if src.RealertSeconds != nil {
		dst.RealertSeconds = *src.RealertSeconds
	}
}

func validateIndustrial(c IndustrialConfig) error {
	rules := []struct {
		id   string
		rule IndustrialRule
	}{
		{RuleModbusWrite, c.ModbusWrite},
		{RuleModbusDiagnostic, c.ModbusDiagnostic},
	}
	for _, r := range rules {
		if !r.rule.Enabled {
			continue
		}
		if !validSeverity(r.rule.Severity) {
			return fmt.Errorf("industrial.%s: unknown severity %q (want low|medium|high)", r.id, r.rule.Severity)
		}
		if r.rule.RealertSeconds < 0 {
			return fmt.Errorf("industrial.%s: realert_seconds must be >= 0", r.id)
		}
		for _, s := range r.rule.AllowedSources {
			if _, err := parsePrefix(s); err != nil {
				return fmt.Errorf("industrial.%s: allowed_sources: %w", r.id, err)
			}
		}
	}
	return nil
}

// SourcePrefixes returns AllowedSources as prefixes. The rule must have
// passed Validate; unparsable entries are dropped.
func (r IndustrialRule) SourcePrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.AllowedSources))
	for _, s := range r.AllowedSources {
		if p, err := parsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
