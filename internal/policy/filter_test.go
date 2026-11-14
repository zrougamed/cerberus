package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// usb0Present lets one test make an interface disappear without swapping
// the resolver under parallel tests.
var usb0Present atomic.Bool

func init() {
	usb0Present.Store(true)
	// Deterministic interfaces for tests: eth0=2, wlan0=3, usb0=4 (toggled).
	ResolveInterface = func(name string) (uint32, error) {
		switch name {
		case "eth0":
			return 2, nil
		case "wlan0":
			return 3, nil
		case "usb0":
			if usb0Present.Load() {
				return 4, nil
			}
		}
		return 0, fmt.Errorf("no such interface")
	}
	InterfaceName = func(idx uint32) string { return map[uint32]string{2: "eth0", 3: "wlan0"}[idx] }
}

func intp(v int) *int { return &v }

func boundEngine(t *testing.T, o Options) (*Engine, *fakeKernel) {
	t.Helper()
	e := openTest(t, o)
	k := newFakeKernel()
	if err := e.Bind(k); err != nil {
		t.Fatal(err)
	}
	return e, k
}

func TestAddFilter_EncodesEveryMatcher(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{})
	r, err := e.AddFilter(FilterInput{
		ID: "ssh-guard",
		Match: FilterMatch{
			Interface: "eth0", Protocol: "TCP", Src: "198.51.100.77/24", SrcNot: true,
			Dst: "10.0.0.5", DstPort: "22", SrcPort: "1024-65535",
			TCPFlagsAny: []string{"SYN"}, TCPFlagsAll: []string{"syn", "ack"},
		},
		Verdict: "block", Log: true, Comment: "guard ssh",
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != VerdictDrop || r.LogEverySeconds != 1 || r.Match.Src != "198.51.100.0/24" ||
		r.Match.Family != "ipv4" || r.Match.Protocol != "tcp" || r.Match.DstPort != "22" {
		t.Fatalf("not normalised: %+v", r)
	}
	if len(k.chain) != 1 {
		t.Fatalf("chain: %+v", k.chain)
	}
	v := k.chain[0]
	want := filterValue{
		Slot: v.Slot, Verdict: fvDrop, Log: 1, Family: 4, L4Proto: 6, Ifindex: 2,
		SportLo: 1024, SportHi: 65535, DportLo: 22, DportHi: 22,
		TCPAny: 0x02, TCPAll: 0x12, MFlags: fmNotSrc, SrcPlen: 24, DstPlen: 32,
		LogIntervalNs: uint64(time.Second),
	}
	copy(want.Src[:], []byte{198, 51, 100, 0})
	copy(want.Dst[:], []byte{10, 0, 0, 5})
	if v != want {
		t.Fatalf("kernel value\n got %+v\nwant %+v", v, want)
	}
	if got := r.Match.Summary(); got != "iface eth0 ipv4 tcp src not 198.51.100.0/24 dst 10.0.0.5/32 sport 1024-65535 dport 22 flags any syn flags all syn,ack" {
		t.Fatalf("summary: %q", got)
	}
}

func TestAddFilter_ICMPv6AndMAC(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{})
	_, err := e.AddFilter(FilterInput{
		Match:   FilterMatch{Protocol: "icmpv6", ICMPType: intp(134), SrcMAC: "02:00:00:00:00:66"},
		Verdict: "drop",
	}, "t")
	if err != nil {
		t.Fatal(err)
	}
	v := k.chain[0]
	if v.Family != 6 || v.L4Proto != 58 || v.ICMPType != 134 || v.MFlags != fmICMPType|fmSMAC || v.SMAC[5] != 0x66 {
		t.Fatalf("kernel value: %+v", v)
	}
}

func TestAddFilter_Validation(t *testing.T) {
	t.Parallel()
	e, _ := boundEngine(t, Options{})
	cases := []struct {
		name string
		in   FilterInput
		want string
	}{
		{"no verdict", FilterInput{Match: FilterMatch{Protocol: "tcp"}}, "verdict is required"},
		{"bad verdict", FilterInput{Verdict: "reject"}, "unknown verdict"},
		{"bad family", FilterInput{Verdict: "accept", Match: FilterMatch{Family: "ipx"}}, "unknown family"},
		{"bad protocol", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "sctpish"}}, "unknown protocol"},
		{"icmp vs ipv6", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "icmp", Family: "ipv6"}}, "contradicts"},
		{"family vs addr", FilterInput{Verdict: "accept", Match: FilterMatch{Family: "ipv6", Src: "10.0.0.1"}}, "does not match family"},
		{"mixed families", FilterInput{Verdict: "accept", Match: FilterMatch{Src: "10.0.0.1", Dst: "2001:db8::1"}}, "does not match family"},
		{"zero prefix", FilterInput{Verdict: "accept", Match: FilterMatch{Src: "0.0.0.0/0"}}, "every address"},
		{"negate nothing", FilterInput{Verdict: "accept", Match: FilterMatch{SrcNot: true}}, "need an address"},
		{"bad mac", FilterInput{Verdict: "accept", Match: FilterMatch{SrcMAC: "nope"}}, "bad src_mac"},
		{"bad port", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "tcp", DstPort: "http"}}, "bad port"},
		{"port zero", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "tcp", DstPort: "0"}}, "bad port range"},
		{"reversed range", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "tcp", DstPort: "90-80"}}, "bad port range"},
		{"ports with icmp", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "icmp", DstPort: "80"}}, "only apply to tcp and udp"},
		{"negate no port", FilterInput{Verdict: "accept", Match: FilterMatch{DstPortNot: true}}, "need a port"},
		{"flags without tcp", FilterInput{Verdict: "accept", Match: FilterMatch{TCPFlagsAny: []string{"syn"}}}, "need protocol tcp"},
		{"bad flag", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "tcp", TCPFlagsAll: []string{"xmas"}}}, "unknown tcp flag"},
		{"icmp type no proto", FilterInput{Verdict: "accept", Match: FilterMatch{ICMPType: intp(8)}}, "need protocol icmp"},
		{"icmp out of range", FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "icmp", ICMPCode: intp(300)}}, "out of range"},
		{"unknown iface", FilterInput{Verdict: "accept", Match: FilterMatch{Interface: "eth9"}}, "interface"},
		{"bad log rate", FilterInput{Verdict: "accept", Log: true, LogEverySeconds: func() *float64 { v := -1.0; return &v }()}, "log_every_seconds"},
		{"bad position", FilterInput{Verdict: "accept", Position: intp(5)}, "position"},
		{"bad id", FilterInput{ID: "a b", Verdict: "accept"}, "id"},
	}
	for _, tc := range cases {
		_, err := e.AddFilter(tc.in, "t")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestAddFilter_SafetyRails(t *testing.T) {
	t.Parallel()
	e, _ := boundEngine(t, Options{Protected: []netip.Addr{netip.MustParseAddr("192.168.1.1")}})
	broad := FilterInput{Verdict: "drop", Match: FilterMatch{Protocol: "tcp", DstPort: "23"}}
	if _, err := e.AddFilter(broad, "t"); !errors.Is(err, ErrProtected) {
		t.Fatalf("broad drop must need force: %v", err)
	}
	broad.Force = true
	if _, err := e.AddFilter(broad, "t"); err != nil {
		t.Fatalf("forced broad drop: %v", err)
	}
	gw := FilterInput{Verdict: "drop", Match: FilterMatch{Dst: "192.168.1.0/24"}}
	if _, err := e.AddFilter(gw, "t"); !errors.Is(err, ErrProtected) {
		t.Fatalf("drop covering gateway must need force: %v", err)
	}
	// Accept and continue rules are never dangerous; negated addresses are
	// not "covering" the protected one.
	if _, err := e.AddFilter(FilterInput{Verdict: "accept", Match: FilterMatch{Protocol: "tcp"}}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddFilter(FilterInput{Verdict: "drop", Match: FilterMatch{Src: "192.168.1.0/24", SrcNot: true, Dst: "10.9.0.0/16"}}, "t"); err != nil {
		t.Fatal(err)
	}
}

func TestFilterChain_OrderMoveToggleRemove(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{})
	add := func(id string, pos *int) {
		t.Helper()
		if _, err := e.AddFilter(FilterInput{ID: id, Verdict: "continue", Match: FilterMatch{Dst: "10.0.0.1"}, Position: pos}, "t"); err != nil {
			t.Fatal(err)
		}
	}
	add("a", nil)
	add("b", nil)
	add("top", intp(0))
	order := func() string {
		var ids []string
		for _, f := range e.Status().Filters {
			ids = append(ids, f.ID)
		}
		return strings.Join(ids, ",")
	}
	if got := order(); got != "top,a,b" {
		t.Fatalf("order after insert: %s", got)
	}
	if err := e.MoveFilter("b", 0, "t"); err != nil {
		t.Fatal(err)
	}
	if got := order(); got != "b,top,a" {
		t.Fatalf("order after move: %s", got)
	}
	if err := e.MoveFilter("b", 9, "t"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad move: %v", err)
	}
	if err := e.MoveFilter("zz", 0, "t"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown move: %v", err)
	}

	if err := e.SetFilterEnabled("top", false, "t"); err != nil {
		t.Fatal(err)
	}
	if len(k.chain) != 2 {
		t.Fatalf("disabled rule must leave the kernel chain: %d", len(k.chain))
	}
	if st := e.Status().Filters[1]; st.ID != "top" || st.Enabled {
		t.Fatalf("disabled rule must stay listed in place: %+v", st)
	}
	if err := e.SetFilterEnabled("top", true, "t"); err != nil || len(k.chain) != 3 {
		t.Fatalf("re-enable: %v, chain %d", err, len(k.chain))
	}
	if err := e.RemoveFilter("top", "t"); err != nil {
		t.Fatal(err)
	}
	if got := order(); got != "b,a" || len(k.chain) != 2 {
		t.Fatalf("after remove: %s chain=%d", got, len(k.chain))
	}
	if err := e.RemoveFilter("top", "t"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	// IDs are unique across blocklist rules and filters.
	if _, err := e.Add(RuleInput{ID: "a", Action: "log", CIDR: "10.1.1.1"}, "t"); !errors.Is(err, ErrConflict) {
		t.Fatalf("blocklist id clash: %v", err)
	}
}

func TestFilterChain_KernelFailureRollsBack(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{StatePath: filepath.Join(t.TempDir(), "p.json")})
	if _, err := e.AddFilter(FilterInput{ID: "keep", Verdict: "accept"}, "t"); err != nil {
		t.Fatal(err)
	}
	k.failChain = errors.New("map busy")
	if _, err := e.AddFilter(FilterInput{ID: "new", Verdict: "accept"}, "t"); err == nil {
		t.Fatal("expected error")
	}
	if err := e.RemoveFilter("keep", "t"); err == nil {
		t.Fatal("expected error")
	}
	if n := len(e.Status().Filters); n != 1 {
		t.Fatalf("state must be rolled back, have %d filters", n)
	}
	k.failChain = nil
	if _, err := e.AddFilter(FilterInput{ID: "new", Verdict: "accept"}, "t"); err != nil {
		t.Fatalf("slot must be free again: %v", err)
	}
}

func TestFilterChain_PersistenceExpiryAndMissingInterface(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "p.json")
	e := openTest(t, Options{StatePath: path, Now: c.now})
	for _, in := range []FilterInput{
		{ID: "first", Verdict: "accept", Match: FilterMatch{Interface: "usb0"}},
		{ID: "temp", Verdict: "continue", TTLSeconds: 60},
		{ID: "last", Verdict: "drop", Match: FilterMatch{Src: "203.0.113.0/24"}, Log: true},
	} {
		if _, err := e.AddFilter(in, "t"); err != nil {
			t.Fatal(err)
		}
	}
	// usb0 is unplugged before the restart.
	usb0Present.Store(false)
	defer usb0Present.Store(true)
	c.add(2 * time.Minute)
	e2 := openTest(t, Options{StatePath: path, Now: c.now})
	var ids []string
	for _, f := range e2.Status().Filters {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, ",") != "first,last" {
		t.Fatalf("reloaded order: %v", ids)
	}
	k := newFakeKernel()
	if err := e2.Bind(k); err != nil {
		t.Fatal(err)
	}
	if k.chain[0].Ifindex != noInterface {
		t.Fatalf("rule on a missing interface must match nothing, got ifindex %d", k.chain[0].Ifindex)
	}

	// TTL expiry while running.
	e3, k3 := boundEngine(t, Options{Now: c.now})
	if _, err := e3.AddFilter(FilterInput{ID: "t1", Verdict: "continue", TTLSeconds: 30}, "t"); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	if got := e3.Expire(); len(got) != 1 || got[0].ID != "t1" || len(k3.chain) != 0 {
		t.Fatalf("expire: %+v chain=%d", got, len(k3.chain))
	}
}

func TestOpen_RejectsBadStoredFilter(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(p, []byte(`{"filters":[{"id":"x","verdict":"explode"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{StatePath: p}); err == nil {
		t.Fatal("expected error")
	}
}

func TestPollHits_Filters(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{})
	if _, err := e.AddFilter(FilterInput{ID: "f", Verdict: "drop", Match: FilterMatch{Src: "203.0.113.0/24"}}, "t"); err != nil {
		t.Fatal(err)
	}
	k.fcounters[k.chain[0].Slot] = Counter{Packets: 4, Bytes: 400}
	hits := e.PollHits()
	if len(hits) != 1 || hits[0].Filter == nil || hits[0].Filter.ID != "f" || hits[0].Delta.Packets != 4 || hits[0].Enforced {
		t.Fatalf("hits: %+v", hits)
	}
	if st := e.Status().Filters[0]; st.Counters.Packets != 4 {
		t.Fatalf("status counters: %+v", st)
	}
}

func rawEvent(t *testing.T, ev logEvent) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.NativeEndian, ev); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRecordLog(t *testing.T) {
	t.Parallel()
	e, k := boundEngine(t, Options{})
	if _, err := e.AddFilter(FilterInput{ID: "ssh", Verdict: "drop", Log: true, Match: FilterMatch{Protocol: "tcp", Dst: "10.0.0.5", DstPort: "22"}}, "t"); err != nil {
		t.Fatal(err)
	}
	ev := logEvent{Slot: k.chain[0].Slot, Ifindex: 2, PktLen: 60, Verdict: fvDrop, Enforced: 1, Family: 4, Proto: 6,
		Sport: 40000, Dport: 22, TCPFlags: 0x02, SMAC: [6]byte{2, 0, 0, 0, 0, 0x10}}
	copy(ev.Src[:], []byte{198, 51, 100, 7})
	copy(ev.Dst[:], []byte{10, 0, 0, 5})
	if err := e.RecordLog(rawEvent(t, ev)); err != nil {
		t.Fatal(err)
	}
	icmp := logEvent{Slot: 63, Family: 6, Proto: 58, ICMPType: 128, Verdict: fvContinue}
	copy(icmp.Src[:], netip.MustParseAddr("2001:db8::1").AsSlice())
	if err := e.RecordLog(rawEvent(t, icmp)); err != nil {
		t.Fatal(err)
	}
	if err := e.RecordLog([]byte{1, 2, 3}); err == nil {
		t.Fatal("short record must fail")
	}

	logs := e.Logs(10)
	if len(logs) != 2 {
		t.Fatalf("logs: %+v", logs)
	}
	newest, first := logs[0], logs[1]
	if newest.RuleID != "slot-63" || newest.Protocol != "icmpv6" || newest.Src != "2001:db8::1" || *newest.ICMPType != 128 {
		t.Fatalf("icmp entry: %+v", newest)
	}
	if first.RuleID != "ssh" || !first.Dropped || first.Interface != "eth0" || first.Src != "198.51.100.7" ||
		first.DstPort != 22 || first.TCPFlags != "syn" || first.SrcMAC != "02:00:00:00:00:10" || first.Verdict != VerdictDrop {
		t.Fatalf("tcp entry: %+v", first)
	}
	if got := e.Logs(1); len(got) != 1 || got[0].RuleID != "slot-63" {
		t.Fatalf("limit: %+v", got)
	}
	for range maxLogs + 10 {
		_ = e.RecordLog(rawEvent(t, ev))
	}
	if n := len(e.Logs(0)); n != maxLogs {
		t.Fatalf("log buffer not capped: %d", n)
	}
}

func TestSizesMatchC(t *testing.T) {
	t.Parallel()
	if n := binary.Size(filterValue{}); n != 80 {
		t.Fatalf("filterValue is %d bytes, struct filter_rule is 80", n)
	}
	if n := binary.Size(logEvent{}); n != 72 {
		t.Fatalf("logEvent is %d bytes, struct filter_log_event is 72", n)
	}
}
