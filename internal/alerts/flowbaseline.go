package alerts

import "fmt"

// RuleBaselineNewFlow fires for an industrial flow first seen after the
// learning period.
const RuleBaselineNewFlow = "baseline_new_flow"

// FlowBaselineConfig controls the industrial flow baseline: during the
// learning period every (client, server, protocol, operation class) tuple
// is recorded; afterwards a tuple not in the baseline raises an alert.
type FlowBaselineConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// LearningHours is how long a fresh baseline learns before it alerts.
	LearningHours int    `yaml:"learning_hours" json:"learning_hours"`
	Severity      string `yaml:"severity" json:"severity"`
	// MaxFlows bounds memory and storage; past it new flows are counted
	// as dropped and neither stored nor alerted on.
	MaxFlows int `yaml:"max_flows" json:"max_flows"`
}

type flowBaselineOverlay struct {
	Enabled       *bool   `yaml:"enabled" json:"enabled"`
	LearningHours *int    `yaml:"learning_hours" json:"learning_hours"`
	Severity      *string `yaml:"severity" json:"severity"`
	MaxFlows      *int    `yaml:"max_flows" json:"max_flows"`
}

const (
	// A week covers weekly batch jobs and shift patterns on most sites.
	defaultLearningHours = 7 * 24
	defaultMaxFlows      = 10000
	maxMaxFlows          = 100000
)

func defaultFlowBaseline() FlowBaselineConfig {
	return FlowBaselineConfig{Enabled: true, LearningHours: defaultLearningHours, Severity: "medium", MaxFlows: defaultMaxFlows}
}

func mergeFlowBaseline(dst *FlowBaselineConfig, src *flowBaselineOverlay) {
	if src == nil {
		return
	}
	if src.Enabled != nil {
		dst.Enabled = *src.Enabled
	}
	if src.LearningHours != nil {
		dst.LearningHours = *src.LearningHours
	}
	if src.Severity != nil {
		dst.Severity = *src.Severity
	}
	if src.MaxFlows != nil {
		dst.MaxFlows = *src.MaxFlows
	}
}

func validateFlowBaseline(c FlowBaselineConfig) error {
	if !c.Enabled {
		return nil
	}
	if c.LearningHours < 1 {
		return fmt.Errorf("flow_baseline.learning_hours must be >= 1")
	}
	if !validSeverity(c.Severity) {
		return fmt.Errorf("flow_baseline: unknown severity %q (want low|medium|high)", c.Severity)
	}
	if c.MaxFlows < 1 || c.MaxFlows > maxMaxFlows {
		return fmt.Errorf("flow_baseline.max_flows must be between 1 and %d", maxMaxFlows)
	}
	return nil
}
