package alerts

import (
	"strings"

	"github.com/zrougamed/cerberus/internal/models"
)

// Technique is a MITRE ATT&CK for ICS technique.
type Technique = models.Technique

// ATT&CK for ICS techniques referenced by the built-in rules
// (https://attack.mitre.org/techniques/ics/).
var (
	techUnauthorizedCommand = Technique{ID: "T0855", Name: "Unauthorized Command Message"}
	techModifyParameter     = Technique{ID: "T0836", Name: "Modify Parameter"}
	techProgramDownload     = Technique{ID: "T0843", Name: "Program Download"}
	techModifyProgram       = Technique{ID: "T0889", Name: "Modify Program"}
	techDeviceRestart       = Technique{ID: "T0816", Name: "Device Restart/Shutdown"}
	techChangeOperatingMode = Technique{ID: "T0858", Name: "Change Operating Mode"}
	techBlockReporting      = Technique{ID: "T0804", Name: "Block Reporting Message"}
	techRemoteDiscovery     = Technique{ID: "T0846", Name: "Remote System Discovery"}
	techAdversaryInMiddle   = Technique{ID: "T0830", Name: "Adversary-in-the-Middle"}
	techModuleFirmware      = Technique{ID: "T0839", Name: "Module Firmware"}
	techRemoteServices      = Technique{ID: "T0886", Name: "Remote Services"}
)

// ruleTechniques maps every built-in rule id to its techniques. An empty
// list is a deliberate "no single technique fits" (a raw volume count, an
// operator-defined watchlist), so a missing entry is always a mistake;
// TestRuleTechniques_CoverEveryBuiltinRule enforces that.
var ruleTechniques = map[string][]Technique{
	// Threshold and infrastructure baselines.
	"dns_query_volume":      nil,
	"tcp_connection_volume": nil,
	"target_spread":         {techRemoteDiscovery},
	"rogue_dhcp_server":     {techAdversaryInMiddle},
	"rogue_ipv6_ra_source":  {techAdversaryInMiddle},
	"gateway_mac_changed":   {techAdversaryInMiddle},

	// Industrial protocols.
	RuleModbusWrite:      {techUnauthorizedCommand, techModifyParameter},
	RuleModbusDiagnostic: {techDeviceRestart},
	RuleS7Write:          {techUnauthorizedCommand, techModifyParameter},
	RuleS7Control:        {techChangeOperatingMode},
	RuleS7Program:        {techProgramDownload, techModifyProgram},
	RuleDNP3Control:      {techUnauthorizedCommand},
	RuleDNP3Diagnostic:   {techDeviceRestart, techBlockReporting},
	RuleENIPWrite:        {techUnauthorizedCommand, techModifyParameter},
	RuleENIPControl:      {techDeviceRestart},
	RuleBACnetWrite:      {techUnauthorizedCommand, techModifyParameter},
	RuleBACnetControl:    {techDeviceRestart, techBlockReporting},
	RuleIEC104Control:    {techUnauthorizedCommand},
	RuleIEC104Diagnostic: {techDeviceRestart},
	RuleOPCUAWrite:       {techUnauthorizedCommand, techModifyParameter},
	RuleOPCUAInsecure:    {techAdversaryInMiddle},
	// An anonymous broker login is a weakness, not an attack step.
	RuleMQTTAnonymous: nil,
	RuleAssetChanged:  {techModuleFirmware},

	// Flows and segmentation: a new path to a controller is how lateral
	// movement shows up on the wire.
	RuleBaselineNewFlow: {techRemoteServices},
	RuleZoneNoConduit:   {techRemoteServices},
	RuleZoneLevelSkip:   {techRemoteServices},
}

// rulePrefixTechniques covers rule families with generated ids.
var rulePrefixTechniques = map[string][]Technique{
	"watchlist:": nil, // operator-defined lists, meaning unknown
	"policy:":    nil, // hits on operator-defined blocklist entries
	"filter:":    nil, // hits on operator-defined filter rules
}

// TechniquesFor returns the ATT&CK for ICS techniques for a rule id, or nil.
// User-defined threshold rules have none.
func TechniquesFor(rule string) []Technique {
	if t, ok := ruleTechniques[rule]; ok {
		return t
	}
	for prefix, t := range rulePrefixTechniques {
		if strings.HasPrefix(rule, prefix) {
			return t
		}
	}
	return nil
}

// BuiltinRuleIDs lists the fixed rule ids the monitor can raise, for tests
// and documentation.
func BuiltinRuleIDs() []string {
	ids := []string{
		"dns_query_volume", "tcp_connection_volume", "target_spread",
		"rogue_dhcp_server", "rogue_ipv6_ra_source", "gateway_mac_changed",
		RuleBaselineNewFlow, RuleZoneNoConduit, RuleZoneLevelSkip,
	}
	cfg := DefaultConfig().Industrial
	for _, r := range cfg.Rules() {
		ids = append(ids, r.ID)
	}
	return ids
}
