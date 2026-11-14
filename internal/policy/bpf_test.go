package policy

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// End-to-end check of the classifier's policy code: load build/cerberus_tc.o,
// drive the engine against the real maps, and run crafted frames through the
// program with BPF_PROG_TEST_RUN (nothing is attached to an interface).
// Needs root/CAP_BPF and `make bpf`; skipped otherwise:
//
//	make bpf && sudo -E go test -run BPF -v ./internal/policy

const (
	verdictNext = 0xFFFFFFFF // TC_ACT_UNSPEC (-1) as returned by the test run
	verdictDrop = 2          // TC_ACT_SHOT
)

func loadClassifier(t *testing.T) (*ebpf.Collection, *ebpf.Program) {
	t.Helper()
	const obj = "../../build/cerberus_tc.o"
	if _, err := os.Stat(obj); errors.Is(err, os.ErrNotExist) {
		t.Skip("build/cerberus_tc.o not built; run make bpf")
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("loading BPF needs root/CAP_BPF")
		}
		t.Fatalf("new collection: %v", err)
	}
	t.Cleanup(coll.Close)
	prog := coll.Programs["xdp_arp_monitor"]
	if prog == nil {
		t.Fatal("classifier program missing")
	}
	return coll, prog
}

// frame builds Ethernet + IPv4/IPv6 + a TCP SYN to port 443.
func frame(srcMAC string, src, dst netip.Addr) []byte {
	mac, _ := net.ParseMAC(srcMAC)
	b := make([]byte, 0, 128)
	b = append(b, 0x02, 0, 0, 0, 0, 0x01) // dst MAC
	b = append(b, mac...)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	if src.Is4() {
		b = binary.BigEndian.AppendUint16(b, 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		ip[8], ip[9] = 64, 6
		s, d := src.As4(), dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		b = append(b, ip...)
	} else {
		b = binary.BigEndian.AppendUint16(b, 0x86DD)
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
		ip[6], ip[7] = 6, 64
		s, d := src.As16(), dst.As16()
		copy(ip[8:], s[:])
		copy(ip[24:], d[:])
		b = append(b, ip...)
	}
	return append(b, tcp...)
}

func run(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret
}

func TestBPF_PolicyVerdictsAndCounters(t *testing.T) {
	coll, prog := loadClassifier(t)
	k, err := NewBPFMaps(coll.Maps)
	if err != nil {
		t.Fatal(err)
	}
	e := openTest(t, Options{})
	if err := e.Bind(k); err != nil {
		t.Fatal(err)
	}

	a := netip.MustParseAddr
	lan, c2, scanner := a("10.0.0.5"), a("203.0.113.9"), a("198.51.100.7")
	host := "02:00:00:00:00:10"

	if got := run(t, prog, frame(host, lan, c2)); got != verdictNext {
		t.Fatalf("no rules: verdict %#x, want next", got)
	}

	mustAdd := func(in RuleInput) Rule {
		t.Helper()
		r, err := e.Add(in, "test")
		if err != nil {
			t.Fatalf("add %+v: %v", in, err)
		}
		return r
	}
	mustAdd(RuleInput{ID: "c2", Action: "drop", CIDR: "203.0.113.0/24", Direction: "dst"})
	mustAdd(RuleInput{ID: "scan", Action: "log", CIDR: scanner.String(), Direction: "src"})
	mustAdd(RuleInput{ID: "cam", Action: "drop", MAC: "02:00:00:00:00:66"})
	mustAdd(RuleInput{ID: "v6", Action: "drop", CIDR: "2001:db8:bad::/48"})

	// Monitor mode: everything counted, nothing dropped.
	if got := run(t, prog, frame(host, lan, c2)); got != verdictNext {
		t.Fatalf("monitor mode must not drop: %#x", got)
	}

	if err := e.SetMode(ModeEnforce, "test"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"dst in dropped prefix", frame(host, lan, c2), verdictDrop},
		{"src only, dst rule ignores it", frame(host, c2, lan), verdictNext},
		{"log rule never drops", frame(host, scanner, lan), verdictNext},
		{"quarantined mac", frame("02:00:00:00:00:66", lan, a("10.0.0.1")), verdictDrop},
		{"ipv6 any direction", frame(host, a("fd00::5"), a("2001:db8:bad::1")), verdictDrop},
		{"unrelated traffic", frame(host, lan, a("192.0.2.1")), verdictNext},
	}
	for _, tc := range cases {
		if got := run(t, prog, tc.pkt); got != tc.want {
			t.Errorf("%s: verdict %#x, want %#x", tc.name, got, tc.want)
		}
	}

	byID := map[string]Counter{}
	for _, r := range e.Status().Rules {
		byID[r.ID] = r.Counters
	}
	want := map[string]uint64{"c2": 2, "scan": 1, "cam": 1, "v6": 1}
	for id, n := range want {
		if byID[id].Packets != n {
			t.Errorf("rule %s: %d packets, want %d", id, byID[id].Packets, n)
		}
	}

	// Removing a rule takes effect immediately.
	if err := e.Remove("c2", "test"); err != nil {
		t.Fatal(err)
	}
	if got := run(t, prog, frame(host, lan, c2)); got != verdictNext {
		t.Fatalf("after remove: verdict %#x, want next", got)
	}
}

// Unprivileged layout check: the object's policy maps must match the Go
// structs that encode their keys and values.
func TestObjectPolicyMapsMatchLayout(t *testing.T) {
	const obj = "../../build/cerberus_tc.o"
	if _, err := os.Stat(obj); errors.Is(err, os.ErrNotExist) {
		t.Skip("build/cerberus_tc.o not built; run make bpf")
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		typ        ebpf.MapType
		key, value uint32
	}{
		"policy_cfg":      {ebpf.Array, 4, 4},
		"policy_mac":      {ebpf.Hash, uint32(binary.Size(macKey{})), uint32(binary.Size(value{}))},
		"policy_v4":       {ebpf.LPMTrie, uint32(binary.Size(v4Key{})), uint32(binary.Size(value{}))},
		"policy_v6":       {ebpf.LPMTrie, uint32(binary.Size(v6Key{})), uint32(binary.Size(value{}))},
		"policy_counters": {ebpf.PerCPUArray, 4, uint32(binary.Size(perCPUCounter{}))},
	}
	for name, w := range want {
		m := spec.Maps[name]
		if m == nil {
			t.Errorf("%s missing", name)
			continue
		}
		if m.Type != w.typ || m.KeySize != w.key || m.ValueSize != w.value {
			t.Errorf("%s: type=%v key=%d value=%d, want type=%v key=%d value=%d",
				name, m.Type, m.KeySize, m.ValueSize, w.typ, w.key, w.value)
		}
		if name != "policy_cfg" && m.MaxEntries != MaxRules {
			t.Errorf("%s: max_entries %d, want %d", name, m.MaxEntries, MaxRules)
		}
	}
}
