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
	RuleDNP3Control      = "dnp3_control"
	RuleDNP3Diagnostic   = "dnp3_diagnostic"
	RuleENIPWrite        = "enip_write"
	RuleENIPControl      = "enip_control"
	RuleBACnetWrite      = "bacnet_write"
	RuleBACnetControl    = "bacnet_control"
	RuleIEC104Control    = "iec104_control"
	RuleIEC104Diagnostic = "iec104_diagnostic"
	RuleOPCUAWrite       = "opcua_write"
	RuleOPCUAInsecure    = "opcua_insecure"
	RuleMQTTAnonymous    = "mqtt_anonymous"
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
	DNP3Control      IndustrialRule `yaml:"dnp3_control" json:"dnp3_control"`
	DNP3Diagnostic   IndustrialRule `yaml:"dnp3_diagnostic" json:"dnp3_diagnostic"`
	ENIPWrite        IndustrialRule `yaml:"enip_write" json:"enip_write"`
	ENIPControl      IndustrialRule `yaml:"enip_control" json:"enip_control"`
	BACnetWrite      IndustrialRule `yaml:"bacnet_write" json:"bacnet_write"`
	BACnetControl    IndustrialRule `yaml:"bacnet_control" json:"bacnet_control"`
	IEC104Control    IndustrialRule `yaml:"iec104_control" json:"iec104_control"`
	IEC104Diagnostic IndustrialRule `yaml:"iec104_diagnostic" json:"iec104_diagnostic"`
	OPCUAWrite       IndustrialRule `yaml:"opcua_write" json:"opcua_write"`
	OPCUAInsecure    IndustrialRule `yaml:"opcua_insecure" json:"opcua_insecure"`
	MQTTAnonymous    IndustrialRule `yaml:"mqtt_anonymous" json:"mqtt_anonymous"`
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
		{RuleDNP3Control, &c.DNP3Control},
		{RuleDNP3Diagnostic, &c.DNP3Diagnostic},
		{RuleENIPWrite, &c.ENIPWrite},
		{RuleENIPControl, &c.ENIPControl},
		{RuleBACnetWrite, &c.BACnetWrite},
		{RuleBACnetControl, &c.BACnetControl},
		{RuleIEC104Control, &c.IEC104Control},
		{RuleIEC104Diagnostic, &c.IEC104Diagnostic},
		{RuleOPCUAWrite, &c.OPCUAWrite},
		{RuleOPCUAInsecure, &c.OPCUAInsecure},
		{RuleMQTTAnonymous, &c.MQTTAnonymous},
	}
}

type industrialRuleOverlay struct {
	Enabled        *bool    `yaml:"enabled" json:"enabled"`
	Severity       *string  `yaml:"severity" json:"severity"`
	AllowedSources []string `yaml:"allowed_sources" json:"allowed_sources"`
	RealertSeconds *int     `yaml:"realert_seconds" json:"realert_seconds"`
}

// industrialOverlay maps rule ids to their file settings. Unknown ids are
// rejected so a typo does not silently leave a rule at its default.
type industrialOverlay map[string]*industrialRuleOverlay

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
		// Operate and restart commands come from the master only, and
		// rarely; anything else sending them is worth a page.
		DNP3Control:    rule("high"),
		DNP3Diagnostic: rule("high"),
		// Tag writes from HMIs are routine, like S7 write_var.
		ENIPWrite:   rule("medium"),
		ENIPControl: rule("high"),
		// Building systems write setpoints constantly; disabling a device's
		// communication or reinitialising it is rare and disruptive.
		BACnetWrite:   rule("medium"),
		BACnetControl: rule("high"),
		// IEC 104 commands come from the control centre only.
		IEC104Control:    rule("high"),
		IEC104Diagnostic: rule("high"),
		OPCUAWrite:       rule("medium"),
		OPCUAInsecure:    rule("medium"),
		MQTTAnonymous:    rule("medium"),
	}
}

func mergeIndustrial(dst *IndustrialConfig, src industrialOverlay) error {
	rules := dst.Rules()
	known := make(map[string]*IndustrialRule, len(rules))
	for _, r := range rules {
		known[r.ID] = r.Rule
	}
	for id, o := range src {
		rule, ok := known[id]
		if !ok {
			return fmt.Errorf("industrial: unknown rule %q", id)
		}
		mergeIndustrialRule(rule, o)
	}
	return nil
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
