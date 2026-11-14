package policy

import "testing"

func TestHostnameMatches(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"evil.com", "evil.com", true},
		{"Evil.COM", "evil.com", true},
		{"evil.com", "notevil.com", false},
		{"*.evil.com", "a.evil.com", true},
		{"*.evil.com", "evil.com", false},
		{"*.evil.com", "a.b.evil.com", false},
		{"", "evil.com", false},
	}
	for _, c := range cases {
		if got := HostnameMatches(c.pattern, c.name); got != c.want {
			t.Errorf("HostnameMatches(%q,%q)=%v want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestNormalizeHostname(t *testing.T) {
	if _, err := normalizeHostname("*.bad.*.com"); err == nil {
		t.Fatal("expected error for multi-wildcard")
	}
	got, err := normalizeHostname("CDN.Example.COM.")
	if err != nil || got != "cdn.example.com" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSyncHostnamesDerivesMAC(t *testing.T) {
	e := openTest(t, Options{})
	k := newFakeKernel()
	if err := e.Bind(k); err != nil {
		t.Fatal(err)
	}
	r, err := e.Add(RuleInput{Action: ActionDrop, Hostname: "*.evil.com", HostMatch: "dns"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	e.SyncHostnames([]HostDevice{{
		MAC:        "02:00:00:00:00:01",
		DNSDomains: map[string]int{"a.evil.com": 3},
	}})
	st := e.Status()
	var derived int
	for _, rs := range st.Rules {
		if rs.ParentID == r.ID && rs.MAC == "02:00:00:00:00:01" {
			derived++
		}
	}
	if derived != 1 {
		t.Fatalf("expected 1 derived rule, got %d (rules=%v)", derived, st.Rules)
	}
	if _, ok := k.macs["02:00:00:00:00:01"]; !ok {
		t.Fatal("expected MAC installed in kernel")
	}

	e.SyncHostnames(nil) // domain gone
	st = e.Status()
	for _, rs := range st.Rules {
		if rs.ParentID == r.ID {
			t.Fatalf("derived rule should be gone: %+v", rs)
		}
	}
}

func TestAddHostnameOnly(t *testing.T) {
	e := openTest(t, Options{})
	r, err := e.Add(RuleInput{Action: ActionLog, Hostname: "tracker.io", HostMatch: "sni"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if r.Hostname != "tracker.io" || r.HostMatch != "sni" {
		t.Fatalf("unexpected rule: %+v", r)
	}
}
