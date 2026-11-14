package policy

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeKernel records what the engine pushed to the "maps".
type fakeKernel struct {
	enforce  bool
	macs     map[string]value
	prefixes map[netip.Prefix]value
	counters map[uint32]Counter
	failPut  error
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{
		macs:     map[string]value{},
		prefixes: map[netip.Prefix]value{},
		counters: map[uint32]Counter{},
	}
}

func (f *fakeKernel) SetEnforce(on bool) error { f.enforce = on; return nil }
func (f *fakeKernel) PutMAC(m net.HardwareAddr, v value) error {
	if f.failPut != nil {
		return f.failPut
	}
	f.macs[m.String()] = v
	return nil
}
func (f *fakeKernel) DeleteMAC(m net.HardwareAddr) error { delete(f.macs, m.String()); return nil }
func (f *fakeKernel) PutPrefix(p netip.Prefix, v value) error {
	if f.failPut != nil {
		return f.failPut
	}
	f.prefixes[p] = v
	return nil
}
func (f *fakeKernel) DeletePrefix(p netip.Prefix) error     { delete(f.prefixes, p); return nil }
func (f *fakeKernel) ReadCounter(s uint32) (Counter, error) { return f.counters[s], nil }
func (f *fakeKernel) ResetCounter(s uint32) error           { delete(f.counters, s); return nil }

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)} }
func openTest(t *testing.T, o Options) *Engine {
	t.Helper()
	e, err := Open(o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return e
}

func TestAdd_InstallsRulesInKernel(t *testing.T) {
	t.Parallel()
	k := newFakeKernel()
	e := openTest(t, Options{})
	if err := e.Bind(k); err != nil {
		t.Fatal(err)
	}

	r1, err := e.Add(RuleInput{Action: "drop", CIDR: "203.0.113.0/24", Direction: "dst"}, "alice")
	if err != nil {
		t.Fatalf("add cidr: %v", err)
	}
	if !strings.HasPrefix(r1.ID, "r-") || r1.CreatedBy != "alice" {
		t.Fatalf("unexpected rule: %+v", r1)
	}
	v := k.prefixes[netip.MustParsePrefix("203.0.113.0/24")]
	if v.Action != kActionDrop || v.Dir != kDirDst {
		t.Fatalf("kernel value: %+v", v)
	}

	_, err = e.Add(RuleInput{ID: "quarantine-cam", Action: "drop", MAC: "AA-BB-CC-00-11-22"}, "alice")
	if err != nil {
		t.Fatalf("add mac: %v", err)
	}
	if _, ok := k.macs["aa:bb:cc:00:11:22"]; !ok {
		t.Fatalf("mac not installed: %v", k.macs)
	}

	_, err = e.Add(RuleInput{Action: "log", CIDR: "2001:db8::1"}, "bob")
	if err != nil {
		t.Fatalf("add v6 host: %v", err)
	}
	v6 := k.prefixes[netip.MustParsePrefix("2001:db8::1/128")]
	if v6.Action != kActionLog || v6.Dir != kDirSrc|kDirDst {
		t.Fatalf("v6 kernel value: %+v", v6)
	}
	if v6.Slot == v.Slot {
		t.Fatal("rules must get distinct counter slots")
	}
}

func TestAdd_Validation(t *testing.T) {
	t.Parallel()
	e := openTest(t, Options{})
	tests := []struct {
		name string
		in   RuleInput
		want string
	}{
		{"no action", RuleInput{CIDR: "10.0.0.0/8"}, "action is required"},
		{"bad action", RuleInput{Action: "reject", CIDR: "10.0.0.0/8"}, "unknown action"},
		{"no target", RuleInput{Action: "drop"}, "mac or cidr is required"},
		{"both targets", RuleInput{Action: "drop", CIDR: "10.0.0.1", MAC: "02:00:00:00:00:01"}, "not both"},
		{"bad cidr", RuleInput{Action: "drop", CIDR: "10.0.0.0/40"}, "bad cidr"},
		{"bad address", RuleInput{Action: "drop", CIDR: "nope"}, "bad address"},
		{"match all v4", RuleInput{Action: "drop", CIDR: "0.0.0.0/0"}, "every address"},
		{"match all v6", RuleInput{Action: "drop", CIDR: "::/0"}, "every address"},
		{"bad direction", RuleInput{Action: "drop", CIDR: "10.0.0.1", Direction: "both"}, "unknown direction"},
		{"bad mac", RuleInput{Action: "drop", MAC: "zz:zz"}, "bad mac"},
		{"broadcast mac", RuleInput{Action: "drop", MAC: "ff:ff:ff:ff:ff:ff"}, "multicast"},
		{"mac with dst", RuleInput{Action: "drop", MAC: "02:00:00:00:00:01", Direction: "dst"}, "source address only"},
		{"bad id", RuleInput{ID: "has space", Action: "drop", CIDR: "10.0.0.1"}, "id"},
		{"negative ttl", RuleInput{Action: "drop", CIDR: "10.0.0.1", TTLSeconds: -1}, "ttl_seconds"},
		{"long comment", RuleInput{Action: "drop", CIDR: "10.0.0.1", Comment: strings.Repeat("x", 300)}, "comment"},
		{"short mapped prefix", RuleInput{Action: "drop", CIDR: "::ffff:0:0/80"}, "IPv4-mapped"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.Add(tc.in, "t")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestAdd_NormalizesMappedAndHostAddresses(t *testing.T) {
	t.Parallel()
	e := openTest(t, Options{})
	r, err := e.Add(RuleInput{Action: "drop", CIDR: "::ffff:192.0.2.0/120"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if r.CIDR != "192.0.2.0/24" {
		t.Fatalf("mapped prefix not unmapped: %s", r.CIDR)
	}
	r, err = e.Add(RuleInput{Action: "drop", CIDR: "198.51.100.77/24"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if r.CIDR != "198.51.100.0/24" {
		t.Fatalf("prefix not masked: %s", r.CIDR)
	}
}

func TestAdd_ConflictsAndCapacity(t *testing.T) {
	t.Parallel()
	e := openTest(t, Options{})
	if _, err := e.Add(RuleInput{ID: "a", Action: "drop", CIDR: "10.1.0.0/16"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add(RuleInput{ID: "a", Action: "drop", CIDR: "10.2.0.0/16"}, "t"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id: got %v", err)
	}
	if _, err := e.Add(RuleInput{ID: "b", Action: "log", CIDR: "10.1.5.5/16"}, "t"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate prefix: got %v", err)
	}
	// Fill to capacity.
	for i := 1; i < MaxRules; i++ {
		a := netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)})
		if _, err := e.Add(RuleInput{Action: "log", CIDR: a.String()}, "t"); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	if _, err := e.Add(RuleInput{Action: "log", CIDR: "192.0.2.1"}, "t"); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("expected full error, got %v", err)
	}
}

func TestAdd_ProtectedAddresses(t *testing.T) {
	t.Parallel()
	gwMAC, _ := net.ParseMAC("02:00:00:00:00:fe")
	e := openTest(t, Options{
		Protected:    []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.10")},
		ProtectedMAC: []net.HardwareAddr{gwMAC},
	})
	for _, in := range []RuleInput{
		{Action: "drop", CIDR: "192.168.1.0/24"},
		{Action: "drop", CIDR: "192.168.1.10"},
		{Action: "drop", MAC: "02:00:00:00:00:FE"},
	} {
		if _, err := e.Add(in, "t"); !errors.Is(err, ErrProtected) {
			t.Fatalf("%+v: expected ErrProtected, got %v", in, err)
		}
	}
	if _, err := e.Add(RuleInput{Action: "drop", CIDR: "192.168.1.0/24", Force: true}, "t"); err != nil {
		t.Fatalf("force should override: %v", err)
	}
	if _, err := e.Add(RuleInput{Action: "drop", CIDR: "192.168.2.0/24"}, "t"); err != nil {
		t.Fatalf("unrelated prefix: %v", err)
	}
}

func TestAdd_KernelFailureRollsBack(t *testing.T) {
	t.Parallel()
	k := newFakeKernel()
	k.failPut = errors.New("map full")
	dir := t.TempDir()
	e := openTest(t, Options{StatePath: filepath.Join(dir, "policy.json")})
	if err := e.Bind(k); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add(RuleInput{ID: "x", Action: "drop", CIDR: "10.0.0.1"}, "t"); err == nil {
		t.Fatal("expected kernel error")
	}
	if len(e.Status().Rules) != 0 {
		t.Fatal("rule must not stay in memory after a kernel failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state file must not be written after a kernel failure")
	}
	k.failPut = nil
	if _, err := e.Add(RuleInput{ID: "x", Action: "drop", CIDR: "10.0.0.1"}, "t"); err != nil {
		t.Fatalf("slot and id must be free again: %v", err)
	}
}

func TestRemove(t *testing.T) {
	t.Parallel()
	k := newFakeKernel()
	e := openTest(t, Options{})
	_ = e.Bind(k)
	if _, err := e.Add(RuleInput{ID: "a", Action: "drop", MAC: "02:00:00:00:00:01"}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.Remove("a", "t"); err != nil {
		t.Fatal(err)
	}
	if len(k.macs) != 0 {
		t.Fatal("mac still in kernel")
	}
	if err := e.Remove("a", "t"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: got %v", err)
	}
	// Same target can be added again.
	if _, err := e.Add(RuleInput{ID: "a", Action: "log", MAC: "02:00:00:00:00:01"}, "t"); err != nil {
		t.Fatal(err)
	}
}

func TestSetMode(t *testing.T) {
	t.Parallel()
	k := newFakeKernel()
	e := openTest(t, Options{})
	_ = e.Bind(k)
	if e.Mode() != ModeMonitor || k.enforce {
		t.Fatal("default must be monitor (dry run)")
	}
	if err := e.SetMode(ModeEnforce, "alice"); err != nil {
		t.Fatal(err)
	}
	if !k.enforce || e.Mode() != ModeEnforce {
		t.Fatal("enforce not applied")
	}
	if err := e.SetMode("panic", "alice"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if err := e.SetMode(ModeEnforce, "alice"); err != nil {
		t.Fatal("same mode should be a no-op")
	}
	audit := e.Status().Audit
	if len(audit) != 1 || audit[0].Action != "mode" || audit[0].Actor != "alice" {
		t.Fatalf("audit: %+v", audit)
	}
}

func TestPersistence_RoundTripAndBind(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sub", "policy.json")
	c := newClock()
	e := openTest(t, Options{StatePath: path, Now: c.now})
	if _, err := e.Add(RuleInput{ID: "keep", Action: "drop", CIDR: "203.0.113.0/24", Comment: "c2"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add(RuleInput{ID: "temp", Action: "drop", MAC: "02:00:00:00:00:09", TTLSeconds: 60}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.SetMode(ModeEnforce, "t"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", fi.Mode().Perm())
	}

	// Reopen after the TTL has passed: the expired rule is gone.
	c.add(2 * time.Minute)
	e2 := openTest(t, Options{StatePath: path, Now: c.now})
	st := e2.Status()
	if st.Mode != ModeEnforce || len(st.Rules) != 1 || st.Rules[0].ID != "keep" || st.Rules[0].Comment != "c2" {
		t.Fatalf("reloaded state: %+v", st)
	}
	k := newFakeKernel()
	if err := e2.Bind(k); err != nil {
		t.Fatal(err)
	}
	if !k.enforce || len(k.prefixes) != 1 {
		t.Fatalf("bind did not push the policy: enforce=%v prefixes=%v", k.enforce, k.prefixes)
	}
}

func TestOpen_RejectsCorruptState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"garbage":   "{not json",
		"bad mode":  `{"mode":"yolo"}`,
		"bad rule":  `{"rules":[{"id":"x","action":"drop","cidr":"0.0.0.0/0"}]}`,
		"bad id":    `{"rules":[{"id":"bad id","action":"drop","cidr":"10.0.0.1/32"}]}`,
		"duplicate": `{"rules":[{"id":"a","action":"drop","cidr":"10.0.0.1/32"},{"id":"b","action":"log","cidr":"10.0.0.1/32"}]}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StatePath: p}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Open(Options{StatePath: filepath.Join(dir, "missing.json")}); err != nil {
		t.Fatalf("missing file must be an empty policy: %v", err)
	}
}

func TestExpire(t *testing.T) {
	t.Parallel()
	c := newClock()
	k := newFakeKernel()
	e := openTest(t, Options{Now: c.now})
	_ = e.Bind(k)
	if _, err := e.Add(RuleInput{ID: "temp", Action: "drop", CIDR: "198.51.100.1", TTLSeconds: 30}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Add(RuleInput{ID: "perm", Action: "drop", CIDR: "198.51.100.2"}, "t"); err != nil {
		t.Fatal(err)
	}
	if got := e.Expire(); len(got) != 0 {
		t.Fatalf("nothing should expire yet: %v", got)
	}
	c.add(31 * time.Second)
	got := e.Expire()
	if len(got) != 1 || got[0].ID != "temp" {
		t.Fatalf("expired: %+v", got)
	}
	if len(k.prefixes) != 1 {
		t.Fatalf("expired rule still in kernel: %v", k.prefixes)
	}
	last := e.Status().Audit
	if a := last[len(last)-1]; a.Action != "expire" || a.Actor != "ttl" {
		t.Fatalf("audit: %+v", a)
	}
}

func TestPollHits_ReportsGrowthWithRealert(t *testing.T) {
	t.Parallel()
	c := newClock()
	k := newFakeKernel()
	e := openTest(t, Options{Now: c.now, HitRealert: time.Minute})
	if hits := e.PollHits(); hits != nil {
		t.Fatal("no kernel, no hits")
	}
	_ = e.Bind(k)
	r, _ := e.Add(RuleInput{ID: "c2", Action: "drop", CIDR: "203.0.113.0/24"}, "t")
	slot := k.prefixes[netip.MustParsePrefix(r.CIDR)].Slot

	if hits := e.PollHits(); len(hits) != 0 {
		t.Fatalf("no traffic yet: %+v", hits)
	}
	k.counters[slot] = Counter{Packets: 5, Bytes: 500}
	hits := e.PollHits()
	if len(hits) != 1 || hits[0].Delta.Packets != 5 || hits[0].Enforced {
		t.Fatalf("first report (monitor mode): %+v", hits)
	}

	_ = e.SetMode(ModeEnforce, "t")
	k.counters[slot] = Counter{Packets: 8, Bytes: 800}
	if hits := e.PollHits(); len(hits) != 0 {
		t.Fatalf("inside realert window: %+v", hits)
	}
	c.add(2 * time.Minute)
	hits = e.PollHits()
	if len(hits) != 1 || hits[0].Delta.Packets != 3 || hits[0].Total.Packets != 8 || !hits[0].Enforced {
		t.Fatalf("second report: %+v", hits)
	}

	st := e.Status()
	if st.Rules[0].Counters.Packets != 8 || !st.KernelAttached {
		t.Fatalf("status counters: %+v", st)
	}
}
