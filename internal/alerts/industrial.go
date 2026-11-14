package alerts

import (
	"fmt"
	"net/netip"
)

// Rule ids raised by the industrial protocol decoders.
const (
	RuleModbusWrite      = "modbus_write"
	RuleModbusDiagnostic = "modbus_diagnostic"
	RuleS7Write          = "s7_write"
	RuleS7Control        = "s7_control"
	RuleS7Program        = "s7_program"
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
	S7Write          IndustrialRule `yaml:"s7_write" json:"s7_write"`
	S7Control        IndustrialRule `yaml:"s7_control" json:"s7_control"`
	S7Program        IndustrialRule `yaml:"s7_program" json:"s7_program"`
}

// NamedIndustrialRule pairs a rule with its id.
type NamedIndustrialRule struct {
	ID   string
	Rule *IndustrialRule
}

// Rules lists every industrial rule with its id, pointing into c.
func (c *IndustrialConfig) Rules() []NamedIndustrialRule {
	return []NamedIndustrialRule{
		{RuleModbusWrite, &c.ModbusWrite},
		{RuleModbusDiagnostic, &c.ModbusDiagnostic},
		{RuleS7Write, &c.S7Write},
		{RuleS7Control, &c.S7Control},
		{RuleS7Program, &c.S7Program},
	}
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
	S7Write          *industrialRuleOverlay `yaml:"s7_write" json:"s7_write"`
	S7Control        *industrialRuleOverlay `yaml:"s7_control" json:"s7_control"`
	S7Program        *industrialRuleOverlay `yaml:"s7_program" json:"s7_program"`
}

func defaultIndustrialConfig() IndustrialConfig {
	rule := func(severity string) IndustrialRule {
		return IndustrialRule{Enabled: true, Severity: severity, RealertSeconds: defaultIndustrialRealertSeconds}
	}
	return IndustrialConfig{
		ModbusWrite:      rule("high"),
		ModbusDiagnostic: rule("high"),
		// HMIs write tags all day; a write is worth a look, a stop or a
		// download is worth a page.
		S7Write:   rule("medium"),
		S7Control: rule("high"),
		S7Program: rule("high"),
	}
}

func mergeIndustrial(dst *IndustrialConfig, src *industrialOverlay) {
	if src == nil {
		return
	}
	overlays := []*industrialRuleOverlay{src.ModbusWrite, src.ModbusDiagnostic, src.S7Write, src.S7Control, src.S7Program}
	for i, r := range dst.Rules() {
		mergeIndustrialRule(r.Rule, overlays[i])
	}
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
	for _, r := range c.Rules() {
		if !r.Rule.Enabled {
			continue
		}
		if !validSeverity(r.Rule.Severity) {
			return fmt.Errorf("industrial.%s: unknown severity %q (want low|medium|high)", r.ID, r.Rule.Severity)
		}
		if r.Rule.RealertSeconds < 0 {
			return fmt.Errorf("industrial.%s: realert_seconds must be >= 0", r.ID)
		}
		for _, s := range r.Rule.AllowedSources {
			if _, err := parsePrefix(s); err != nil {
				return fmt.Errorf("industrial.%s: allowed_sources: %w", r.ID, err)
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
