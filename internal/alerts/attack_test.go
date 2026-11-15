package alerts

import (
	"regexp"
	"testing"
)

// Every rule the monitor can raise must have an entry, even if empty, so a
// new rule cannot ship without someone deciding on its techniques.
func TestRuleTechniques_CoverEveryBuiltinRule(t *testing.T) {
	t.Parallel()
	for _, id := range BuiltinRuleIDs() {
		if _, ok := ruleTechniques[id]; !ok {
			t.Errorf("rule %q has no ATT&CK entry; add one to ruleTechniques (nil if none fits)", id)
		}
	}
	for _, th := range DefaultConfig().Thresholds {
		if _, ok := ruleTechniques[th.ID]; !ok {
			t.Errorf("default threshold %q has no ATT&CK entry", th.ID)
		}
	}
}

func TestRuleTechniques_WellFormed(t *testing.T) {
	t.Parallel()
	id := regexp.MustCompile(`^T0\d{3}$`)
	names := map[string]string{}
	for rule, techs := range ruleTechniques {
		for _, tech := range techs {
			if !id.MatchString(tech.ID) || tech.Name == "" {
				t.Errorf("rule %q: malformed technique %+v", rule, tech)
			}
			if prev, ok := names[tech.ID]; ok && prev != tech.Name {
				t.Errorf("technique %s has two names: %q and %q", tech.ID, prev, tech.Name)
			}
			names[tech.ID] = tech.Name
		}
	}
}

func TestTechniquesFor(t *testing.T) {
	t.Parallel()
	if got := TechniquesFor(RuleS7Program); len(got) != 2 || got[0].ID != "T0843" || got[1].ID != "T0889" {
		t.Fatalf("s7_program = %+v", got)
	}
	if got := TechniquesFor("gateway_mac_changed"); len(got) != 1 || got[0].Name != "Adversary-in-the-Middle" {
		t.Fatalf("gateway_mac_changed = %+v", got)
	}
	for _, rule := range []string{"watchlist:c2", "policy:r-1", "filter:f-1", "my_custom_threshold", RuleMQTTAnonymous, ""} {
		if got := TechniquesFor(rule); got != nil {
			t.Errorf("%q = %+v, want none", rule, got)
		}
	}
}
