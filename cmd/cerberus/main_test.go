package main

import (
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/policy"
)

func TestPolicyHitAlert(t *testing.T) {
	cases := []struct {
		name     string
		hit      policy.Hit
		severity string
		phrase   string
	}{
		{
			name:     "enforced drop",
			hit:      policy.Hit{Rule: policy.Rule{ID: "c2", Action: policy.ActionDrop, CIDR: "203.0.113.0/24"}, Delta: policy.Counter{Packets: 3}, Total: policy.Counter{Packets: 9}, Enforced: true},
			severity: "high", phrase: "c2 dropped 3 packet(s) for 203.0.113.0/24 (total 9)",
		},
		{
			name:     "dry run",
			hit:      policy.Hit{Rule: policy.Rule{ID: "cam", Action: policy.ActionDrop, MAC: "02:00:00:00:00:66"}, Delta: policy.Counter{Packets: 1}},
			severity: "medium", phrase: "would have dropped (monitor mode) 1 packet(s) for MAC 02:00:00:00:00:66",
		},
		{
			name:     "log rule",
			hit:      policy.Hit{Rule: policy.Rule{ID: "scan", Action: policy.ActionLog, CIDR: "198.51.100.7/32"}, Delta: policy.Counter{Packets: 2}},
			severity: "low", phrase: "scan matched 2 packet(s)",
		},
	}
	for _, tc := range cases {
		a := policyHitAlert(tc.hit)
		if a.Severity != tc.severity || a.Rule != "policy:"+tc.hit.Rule.ID || !strings.Contains(a.Message, tc.phrase) {
			t.Errorf("%s: %+v", tc.name, a)
		}
		if tc.hit.Rule.MAC != "" && a.DeviceMAC != tc.hit.Rule.MAC {
			t.Errorf("%s: device MAC not set", tc.name)
		}
	}
}

func TestFilterHitAlert(t *testing.T) {
	f := &policy.FilterRule{ID: "ssh-drop", Verdict: policy.VerdictDrop, Match: policy.FilterMatch{Protocol: "tcp", DstPort: "22"}}
	a := policyHitAlert(policy.Hit{Filter: f, Delta: policy.Counter{Packets: 2}, Total: policy.Counter{Packets: 5}, Enforced: true})
	if a.Rule != "filter:ssh-drop" || a.Severity != "high" || !strings.Contains(a.Message, "dropped 2 packet(s) matching tcp dport 22 (total 5)") {
		t.Fatalf("enforced: %+v", a)
	}
	a = policyHitAlert(policy.Hit{Filter: f, Delta: policy.Counter{Packets: 1}})
	if a.Severity != "medium" || !strings.Contains(a.Message, "would have dropped") {
		t.Fatalf("dry run: %+v", a)
	}
	acc := &policy.FilterRule{ID: "ok", Verdict: policy.VerdictAccept, Match: policy.FilterMatch{SrcMAC: "02:00:00:00:00:01"}}
	a = policyHitAlert(policy.Hit{Filter: acc, Delta: policy.Counter{Packets: 1}})
	if a.Severity != "low" || !strings.Contains(a.Message, "allowed") || a.DeviceMAC != "02:00:00:00:00:01" {
		t.Fatalf("accept: %+v", a)
	}
}
