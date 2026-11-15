package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

// ipv4Frame builds an Ethernet + IPv4 header frame between two addresses.
func ipv4Frame(src, dst string, vlan bool) []byte {
	f := make([]byte, 12)
	if vlan {
		f = append(f, 0x81, 0x00, 0x00, 0x0A)
	}
	f = append(f, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	return append(f, ip...)
}

func ipv6Frame(src, dst string) []byte {
	f := append(make([]byte, 12), 0x86, 0xDD)
	ip := make([]byte, 40)
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(f, ip...)
}

func arpFrame(sender, target string) []byte {
	f := append(make([]byte, 12), 0x08, 0x06)
	a := make([]byte, 28)
	s, t := netip.MustParseAddr(sender).As4(), netip.MustParseAddr(target).As4()
	copy(a[14:], s[:])
	copy(a[24:], t[:])
	return append(f, a...)
}

func TestHasAddr(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr("10.0.0.5")
	tests := []struct {
		name  string
		frame []byte
		addr  netip.Addr
		want  bool
	}{
		{"ipv4 src", ipv4Frame("10.0.0.5", "10.0.0.9", false), a, true},
		{"ipv4 dst", ipv4Frame("10.0.0.9", "10.0.0.5", false), a, true},
		{"ipv4 other", ipv4Frame("10.0.0.8", "10.0.0.9", false), a, false},
		{"vlan tagged", ipv4Frame("10.0.0.9", "10.0.0.5", true), a, true},
		{"mapped address", ipv4Frame("10.0.0.5", "10.0.0.9", false), netip.MustParseAddr("::ffff:10.0.0.5"), true},
		{"ipv6", ipv6Frame("2001:db8::1", "2001:db8::5"), netip.MustParseAddr("2001:db8::5"), true},
		{"ipv6 vs ipv4 addr", ipv6Frame("2001:db8::1", "2001:db8::5"), a, false},
		{"arp target", arpFrame("10.0.0.1", "10.0.0.5"), a, true},
		{"arp other", arpFrame("10.0.0.1", "10.0.0.6"), a, false},
		{"short frame", []byte{1, 2, 3}, a, false},
		{"truncated ipv4", ipv4Frame("10.0.0.5", "10.0.0.9", false)[:20], a, false},
		{"truncated vlan", append(make([]byte, 12), 0x81, 0x00, 0, 1), a, false},
		{"other ethertype", append(make([]byte, 12), 0x88, 0x92, 0, 0), a, false},
	}
	for _, tt := range tests {
		if got := hasAddr(tt.frame, tt.addr); got != tt.want {
			t.Errorf("%s: hasAddr = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRing_EvictsByAgeAndBytes(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	r := newRing(100, 10*time.Second)
	for i := range 5 {
		r.add(Packet{Time: t0.Add(time.Duration(i) * time.Second), Data: make([]byte, 10)})
	}
	if n, b, oldest := r.stats(); n != 5 || b != 50 || !oldest.Equal(t0) {
		t.Fatalf("stats = %d %d %v", n, b, oldest)
	}
	r.add(Packet{Time: t0.Add(12 * time.Second), Data: make([]byte, 10)}) // evicts t0, t0+1s
	if n, _, oldest := r.stats(); n != 4 || !oldest.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("after age eviction: %d %v", n, oldest)
	}
	// 30 + 10 + 80 bytes: the two oldest go, leaving exactly 100.
	r.add(Packet{Time: t0.Add(13 * time.Second), Data: make([]byte, 80)})
	if n, b, _ := r.stats(); b != 100 || n != 3 {
		t.Fatalf("after byte eviction: %d packets %d bytes", n, b)
	}
	got := r.selectPackets(t0.Add(12*time.Second), t0.Add(12*time.Second), nil)
	if len(got) != 1 {
		t.Fatalf("window select = %d", len(got))
	}
	r2 := newRing(10, time.Second)
	if n, _, oldest := r2.stats(); n != 0 || !oldest.IsZero() {
		t.Fatal("empty ring stats")
	}
}

func TestRing_CompactsUnderSteadyLoad(t *testing.T) {
	t.Parallel()
	r := newRing(1000, time.Hour)
	t0 := time.Now()
	for i := range 10000 {
		r.add(Packet{Time: t0.Add(time.Duration(i) * time.Millisecond), Data: make([]byte, 10)})
	}
	if cap(r.buf) > 1000 {
		t.Fatalf("ring grew to %d slots for 100 live packets", cap(r.buf))
	}
}

// readPcapng walks the blocks and returns their types, checking framing.
func readPcapng(t *testing.T, data []byte) (types []uint32, epbLens []uint32) {
	t.Helper()
	for len(data) > 0 {
		if len(data) < 12 {
			t.Fatalf("trailing %d bytes", len(data))
		}
		typ := binary.LittleEndian.Uint32(data[0:4])
		total := binary.LittleEndian.Uint32(data[4:8])
		if total%4 != 0 || int(total) > len(data) || binary.LittleEndian.Uint32(data[total-4:total]) != total {
			t.Fatalf("bad block framing: type %#x total %d", typ, total)
		}
		if typ == blockSHB && binary.LittleEndian.Uint32(data[8:12]) != byteOrderMagic {
			t.Fatal("bad byte-order magic")
		}
		if typ == blockEPB {
			epbLens = append(epbLens, binary.LittleEndian.Uint32(data[20:24]))
		}
		types = append(types, typ)
		data = data[total:]
	}
	return types, epbLens
}

func TestWritePcapng_Structure(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	pkts := []Packet{
		{Time: time.Unix(1700000000, 123456000), Iface: 0, Data: []byte{1, 2, 3}, OrigLen: 60},
		{Time: time.Unix(1700000001, 0), Iface: 1, Data: make([]byte, 64), OrigLen: 64},
	}
	if err := writePcapng(&b, []Interface{{Name: "eth0", Snaplen: 1518}, {Name: "eth1", Snaplen: 1518}}, pkts); err != nil {
		t.Fatal(err)
	}
	types, lens := readPcapng(t, b.Bytes())
	want := []uint32{blockSHB, blockIDB, blockIDB, blockEPB, blockEPB}
	if len(types) != len(want) {
		t.Fatalf("blocks = %#x", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("blocks = %#x", types)
		}
	}
	if lens[0] != 3 || lens[1] != 64 {
		t.Fatalf("captured lengths = %v", lens)
	}
	if !bytes.Contains(b.Bytes(), []byte("eth1")) {
		t.Fatal("interface name missing")
	}
	// First EPB: find it after SHB + 2 IDBs and decode the timestamp.
	data := b.Bytes()
	for range 3 {
		data = data[binary.LittleEndian.Uint32(data[4:8]):]
	}
	high, low := binary.LittleEndian.Uint32(data[12:16]), binary.LittleEndian.Uint32(data[16:20])
	if got := int64(high)<<32 | int64(low); got != pkts[0].Time.UnixMicro() {
		t.Fatalf("timestamp = %d, want %d", got, pkts[0].Time.UnixMicro())
	}
}

func TestU32Clamps(t *testing.T) {
	t.Parallel()
	if u32(-5) != 0 || u32(7) != 7 || u32(1<<40) != 1<<32-1 {
		t.Fatal("u32 clamping")
	}
	var b bytes.Buffer
	writeOption(&b, optIfName, make([]byte, 70000))
	if got := binary.LittleEndian.Uint16(b.Bytes()[2:4]); got != 65535 {
		t.Fatalf("option length = %d", got)
	}
}

type failWriter struct{ after int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("disk full")
	}
	w.after--
	return len(p), nil
}

func TestWritePcapng_WriteErrors(t *testing.T) {
	t.Parallel()
	pkts := []Packet{{Time: time.Now(), Data: []byte{1}}}
	if err := writePcapng(&failWriter{after: 0}, nil, pkts); err == nil {
		t.Fatal("header write error ignored")
	}
	if err := writePcapng(&failWriter{after: 1}, nil, pkts); err == nil {
		t.Fatal("packet write error ignored")
	}
}

func testConfig() alerts.CaptureConfig {
	c := alerts.DefaultConfig().Capture
	c.Enabled = true
	c.OnAlert.AfterSeconds = 0
	return c
}

// fakeSource emits the given frames once, then waits for cancellation.
type fakeSource struct {
	name   string
	frames [][]byte
	err    error
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Run(ctx context.Context, emit func([]byte, int)) error {
	for _, fr := range f.frames {
		emit(fr, len(fr))
	}
	if f.err != nil {
		return f.err
	}
	<-ctx.Done()
	return nil
}

func newTestCapturer(t *testing.T, cfg alerts.CaptureConfig, srcs ...Source) *Capturer {
	t.Helper()
	c, err := New(cfg, t.TempDir(), srcs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCapturer_SourcesFeedTheRing(t *testing.T) {
	t.Parallel()
	frames := [][]byte{ipv4Frame("10.0.0.5", "10.0.0.9", false), ipv4Frame("10.0.0.7", "10.0.0.9", false)}
	c := newTestCapturer(t, testConfig(), &fakeSource{name: "eth0", frames: frames}, &fakeSource{name: "eth1", err: errors.New("gone")})
	c.Start()
	waitFor(t, func() bool { return c.Status().BufferPackets == 2 })
	s := c.Status()
	if !s.Enabled || len(s.Interfaces) != 2 || s.Interfaces[1] != "eth1" || s.BufferBytes != 68 {
		t.Fatalf("status = %+v", s)
	}
	got, err := c.CaptureNow(netip.MustParseAddr("10.0.0.5"), time.Minute)
	if err != nil || got.Packets != 1 || got.Address != "10.0.0.5" || got.Reason != "manual" {
		t.Fatalf("capture = %+v err=%v", got, err)
	}
	all, err := c.CaptureNow(netip.Addr{}, time.Minute)
	if err != nil || all.Packets != 2 || all.Address != "" {
		t.Fatalf("capture all = %+v err=%v", all, err)
	}
	if _, err := c.CaptureNow(netip.Addr{}, 0); err == nil {
		t.Fatal("zero window accepted")
	}
	if _, err := c.CaptureNow(netip.Addr{}, time.Hour); err == nil {
		t.Fatal("window beyond buffer accepted")
	}
}

func TestCapturer_TriggerForAlert(t *testing.T) {
	t.Parallel()
	c := newTestCapturer(t, testConfig())
	c.ring.add(Packet{Time: time.Now(), Data: ipv4Frame("10.0.0.5", "10.0.0.9", false), OrigLen: 34})
	c.ring.add(Packet{Time: time.Now(), Data: ipv4Frame("10.0.0.8", "10.0.0.9", false), OrigLen: 34})

	alert := models.AlertEvent{ID: "a1", Rule: "s7_control", Severity: "high", DeviceIP: "10.0.0.5"}
	id := c.TriggerForAlert(alert)
	if !captureIDPattern.MatchString(id) {
		t.Fatalf("id = %q", id)
	}
	waitFor(t, func() bool { return len(c.List()) == 1 })
	got := c.List()[0]
	if got.ID != id || got.Rule != "s7_control" || got.AlertID != "a1" || got.Packets != 1 || got.Reason != "alert" {
		t.Fatalf("capture = %+v", got)
	}

	// Same device inside min_interval: skipped. Lower severity: ignored.
	if c.TriggerForAlert(alert) != "" {
		t.Fatal("rate limit ignored")
	}
	if c.TriggerForAlert(models.AlertEvent{Severity: "medium", DeviceIP: "10.0.0.6"}) != "" {
		t.Fatal("below min severity captured")
	}
	if c.TriggerForAlert(models.AlertEvent{Severity: "high", DeviceIP: "not-an-ip"}) != "" {
		t.Fatal("bad address captured")
	}
	if s := c.Status(); s.Skipped != 1 {
		t.Fatalf("skipped = %d", s.Skipped)
	}

	f, meta, err := c.Open(id)
	if err != nil || meta.ID != id {
		t.Fatalf("open: %v", err)
	}
	data, _ := io.ReadAll(f)
	_ = f.Close()
	if types, _ := readPcapng(t, data); len(types) != 2 { // SHB + EPB (no sources, so no IDB)
		t.Fatalf("blocks = %v", types)
	}
	if err := c.Delete(id); err != nil || len(c.List()) != 0 {
		t.Fatalf("delete: %v", err)
	}
	if err := c.Delete(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestCapturer_PendingCapAndStop(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.OnAlert.AfterSeconds = 300 // never fires during the test
	c := newTestCapturer(t, cfg)
	for i := range maxPending + 2 {
		c.TriggerForAlert(models.AlertEvent{Severity: "high", DeviceIP: netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}).String()})
	}
	if s := c.Status(); s.Pending != maxPending || s.Skipped != 2 {
		t.Fatalf("status = %+v", s)
	}
	c.Stop()
	if c.TriggerForAlert(models.AlertEvent{Severity: "high", DeviceIP: "10.0.2.1"}) != "" {
		t.Fatal("trigger after stop")
	}
}

func TestCapturer_RateKeysBounded(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.OnAlert.AfterSeconds = 300
	c := newTestCapturer(t, cfg)
	c.mu.Lock()
	for i := range maxRateKeys {
		c.lastByIP[netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}).String()] = time.Now()
	}
	c.mu.Unlock()
	c.TriggerForAlert(models.AlertEvent{Severity: "high", DeviceIP: "192.0.2.1"})
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lastByIP) != 1 {
		t.Fatalf("rate state = %d", len(c.lastByIP))
	}
}

func TestNew_DisabledAndBadDir(t *testing.T) {
	t.Parallel()
	if _, err := New(alerts.DefaultConfig().Capture, t.TempDir(), nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled err = %v", err)
	}
	cfg := testConfig()
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	cfg.Dir = filepath.Join(blocker, "sub")
	if _, err := New(cfg, "", nil); err == nil {
		t.Fatal("capture dir under a file accepted")
	}
}

func TestStore_RetentionPermissionsAndIDs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := openStore(filepath.Join(dir, "caps"), 2, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(dir, "caps")); info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v", info.Mode().Perm())
	}
	t0 := time.Now()
	var ids []string
	for i := range 3 {
		c, err := s.save(Capture{ID: newCaptureID(), CreatedAt: t0.Add(time.Duration(i) * time.Second)}, nil, []Packet{{Time: t0, Data: []byte{1}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}
	list := s.list()
	if len(list) != 2 || list[0].ID != ids[2] || list[1].ID != ids[1] {
		t.Fatalf("retention kept %+v", list)
	}
	pcap, _ := names(ids[2])
	if info, _ := os.Stat(filepath.Join(s.dir, pcap)); info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v", info.Mode().Perm())
	}
	// ids[0] was removed by retention; ids are lower-case hex only.
	for _, bad := range []string{"../../etc/passwd", strings.Repeat("A", 16), "", ids[0]} {
		if _, _, err := s.open(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("open(%q) err = %v", bad, err)
		}
	}
	if err := s.remove("../x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("traversal remove accepted")
	}
	if _, err := s.save(Capture{ID: "../evil"}, nil, nil); err == nil {
		t.Fatal("bad id saved")
	}
	if _, err := s.save(Capture{ID: ids[2]}, nil, nil); err == nil {
		t.Fatal("existing id overwritten")
	}
	// Byte limit: a 1-byte budget keeps nothing larger than it.
	tiny, _ := openStore(filepath.Join(dir, "tiny"), 10, 1)
	if _, err := tiny.save(Capture{ID: newCaptureID()}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(tiny.list()); n != 0 {
		t.Fatalf("byte retention kept %d", n)
	}
}

func TestStore_SkipsBadMetadataAndMissingFile(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t.TempDir(), 10, 1<<20)
	_ = os.WriteFile(filepath.Join(s.dir, "junk.json"), []byte("{bad"), 0o600)
	_ = os.WriteFile(filepath.Join(s.dir, "x.json"), []byte(`{"id":"../../x"}`), 0o600)
	c, _ := s.save(Capture{ID: newCaptureID(), CreatedAt: time.Now()}, nil, nil)
	if l := s.list(); len(l) != 1 || l[0].ID != c.ID {
		t.Fatalf("list = %+v", l)
	}
	pcap, _ := names(c.ID)
	_ = os.Remove(filepath.Join(s.dir, pcap))
	if _, _, err := s.open(c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open without pcap: %v", err)
	}
}

func TestSeverityRank(t *testing.T) {
	t.Parallel()
	if severityRank("high") <= severityRank("medium") || severityRank("medium") <= severityRank("low") || severityRank("x") != 0 {
		t.Fatal("ranking")
	}
}

func TestCapturer_OpenUnknownAndFailedAlertWrite(t *testing.T) {
	t.Parallel()
	c := newTestCapturer(t, testConfig())
	if _, _, err := c.Open("0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open unknown: %v", err)
	}
	// Remove the directory so the scheduled write fails; the capturer
	// logs it and frees the pending slot. The root keeps its handle on the
	// deleted directory, so creating a file in it fails.
	_ = os.RemoveAll(c.store.dir)
	if id := c.TriggerForAlert(models.AlertEvent{ID: "a", Severity: "high", DeviceIP: "10.0.0.5"}); id == "" {
		t.Fatal("no capture scheduled")
	}
	waitFor(t, func() bool { return c.Status().Pending == 0 })
	if len(c.List()) != 0 {
		t.Fatal("capture listed after failed write")
	}
}

func TestStatus_OldestOnlyWhenBuffered(t *testing.T) {
	t.Parallel()
	c := newTestCapturer(t, testConfig())
	if c.Status().BufferOldest != nil {
		t.Fatal("empty buffer reports an oldest packet")
	}
	ts := time.Now()
	c.ring.add(Packet{Time: ts, Data: []byte{1}})
	if o := c.Status().BufferOldest; o == nil || !o.Equal(ts) {
		t.Fatalf("oldest = %v", o)
	}
}
