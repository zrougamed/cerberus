package monitor

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"
)

func newIndustrialMonitor(t *testing.T, mutate func(*alerts.IndustrialConfig)) *NetworkMonitor {
	t.Helper()
	cfg := alerts.DefaultConfig()
	if mutate != nil {
		mutate(&cfg.Industrial)
	}
	nm, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), cfg)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	return nm
}

// modbusEvent builds a TCP event carrying a Modbus/TCP PDU.
func modbusEvent(srcMAC byte, src, dst string, sport, dport uint16, unit byte, pdu ...byte) *models.NetworkEvent {
	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_TCP,
		Protocol:  6,
		SrcMac:    [6]byte{0x02, 0, 0, 0, 0, srcMAC},
		DstMac:    [6]byte{0x02, 0, 0, 0, 0, 0xFE},
		SrcIP:     ipv4LE(src),
		DstIP:     ipv4LE(dst),
		SrcPort:   sport,
		DstPort:   dport,
		TCPFlags:  0x18,
	}
	frame := []byte{0, 1, 0, 0, 0, byte(len(pdu) + 1), unit}
	copy(evt.L7Payload[:], append(frame, pdu...))
	return evt
}

// ipv4LE matches how the TC program stores addresses (network order read
// as a little-endian uint32).
func ipv4LE(s string) uint32 {
	var b [4]byte
	_, _ = fmt.Sscanf(s, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return binary.LittleEndian.Uint32(b[:])
}

func industrialAlerts(nm *NetworkMonitor) []models.AlertEvent {
	var out []models.AlertEvent
	for _, a := range nm.GetAlerts() {
		if strings.HasPrefix(a.Rule, "modbus_") {
			out = append(out, a)
		}
	}
	return out
}

func TestTrackEvent_ModbusWriteRaisesAlertAndCounts(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x03, 0, 0, 0, 10))
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x10, 0, 1, 0, 2, 4, 0, 1, 0, 2))

	got := industrialAlerts(nm)
	if len(got) != 1 {
		t.Fatalf("alerts = %+v, want one modbus_write", got)
	}
	a := got[0]
	if a.Rule != alerts.RuleModbusWrite || a.Severity != "high" || a.DeviceMAC != "02:00:00:00:00:01" {
		t.Fatalf("unexpected alert: %+v", a)
	}
	want := "Modbus write_multiple_registers from 10.0.0.9 to 10.0.0.5 unit 1, address 1 count 2"
	if a.Message != want {
		t.Fatalf("message = %q, want %q", a.Message, want)
	}

	s := nm.GetStats()["02:00:00:00:00:01"].Industrial[industrial.ProtocolModbus]
	if s == nil || s.Requests != 2 || s.Operations["read"] != 1 || s.Operations["write"] != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if s.Functions["write_multiple_registers"] != 1 || len(s.Peers) != 1 || s.Peers[0] != "10.0.0.5" {
		t.Fatalf("stats = %+v", s)
	}

	counts := nm.GetIndustrialCounts()
	if counts[IndustrialCountKey{Protocol: "modbus", Class: "write"}] != 1 ||
		counts[IndustrialCountKey{Protocol: "modbus", Class: "read"}] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestTrackEvent_ModbusResponseCountsOnServer(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(modbusEvent(5, "10.0.0.5", "10.0.0.9", 502, 50000, 1, 0x10, 0, 1, 0, 2))
	nm.TrackEvent(modbusEvent(5, "10.0.0.5", "10.0.0.9", 502, 50000, 1, 0x90, 0x02))

	if got := industrialAlerts(nm); len(got) != 0 {
		t.Fatalf("responses must not alert: %+v", got)
	}
	s := nm.GetStats()["02:00:00:00:00:05"].Industrial[industrial.ProtocolModbus]
	if s.Responses != 2 || s.Exceptions != 1 || s.Requests != 0 || len(s.Operations) != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTrackEvent_ModbusDiagnosticAlert(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 3, 0x08, 0x00, 0x04, 0x00, 0x00))
	got := industrialAlerts(nm)
	if len(got) != 1 || got[0].Rule != alerts.RuleModbusDiagnostic {
		t.Fatalf("alerts = %+v", got)
	}
	if want := "Modbus diagnostics from 10.0.0.9 to 10.0.0.5 unit 3"; got[0].Message != want {
		t.Fatalf("message = %q, want %q", got[0].Message, want)
	}
}

func TestTrackEvent_ModbusAllowedSourceIsSilent(t *testing.T) {
	nm := newIndustrialMonitor(t, func(c *alerts.IndustrialConfig) {
		c.ModbusWrite.AllowedSources = []string{"10.0.0.0/28"}
	})
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x06, 0, 1, 0, 3))
	nm.TrackEvent(modbusEvent(2, "10.0.0.20", "10.0.0.5", 50000, 502, 1, 0x06, 0, 1, 0, 3))

	got := industrialAlerts(nm)
	if len(got) != 1 || got[0].DeviceIP != "10.0.0.20" {
		t.Fatalf("only the source outside the allow-list should alert: %+v", got)
	}
	if s := nm.GetStats()["02:00:00:00:00:01"].Industrial["modbus"]; s.Operations["write"] != 1 {
		t.Fatalf("allowed writes must still be counted: %+v", s)
	}
}

func TestTrackEvent_ModbusDisabledRule(t *testing.T) {
	nm := newIndustrialMonitor(t, func(c *alerts.IndustrialConfig) {
		c.ModbusWrite.Enabled = false
	})
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x06, 0, 1, 0, 3))
	if got := industrialAlerts(nm); len(got) != 0 {
		t.Fatalf("disabled rule fired: %+v", got)
	}
}

func TestTrackEvent_NonModbusOnPort502Ignored(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	evt := modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1)
	evt.L7Payload = [models.L7PayloadSize]byte{} // bare ACK
	nm.TrackEvent(evt)
	if d := nm.GetStats()["02:00:00:00:00:01"]; d.Industrial != nil {
		t.Fatalf("empty payload decoded: %+v", d.Industrial)
	}
}

func TestCheckIndustrialAlert_RealertWindowPerTargetAndUnit(t *testing.T) {
	nm := newIndustrialMonitor(t, func(c *alerts.IndustrialConfig) {
		c.ModbusWrite.RealertSeconds = 600
	})
	device := &models.DeviceInfo{MAC: "02:00:00:00:00:01", IP: "10.0.0.9"}
	write := industrial.Message{Protocol: "modbus", Class: industrial.ClassWrite, FunctionName: "write_single_register", Unit: 1}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	nm.mu.Lock()
	nm.checkIndustrialAlert(device, write, "10.0.0.9", "10.0.0.5", t0)
	nm.checkIndustrialAlert(device, write, "10.0.0.9", "10.0.0.5", t0.Add(time.Minute)) // inside window
	nm.checkIndustrialAlert(device, write, "10.0.0.9", "10.0.0.6", t0.Add(time.Minute)) // other target
	other := write
	other.Unit = 2
	nm.checkIndustrialAlert(device, other, "10.0.0.9", "10.0.0.5", t0.Add(time.Minute)) // other unit
	nm.checkIndustrialAlert(device, write, "10.0.0.9", "10.0.0.5", t0.Add(11*time.Minute))
	nm.mu.Unlock()

	if got := industrialAlerts(nm); len(got) != 4 {
		t.Fatalf("alerts = %d, want 4: %+v", len(got), got)
	}
}

func TestPruneIndustrialState_AtCap(t *testing.T) {
	nm := newIndustrialMonitor(t, func(c *alerts.IndustrialConfig) {
		c.ModbusWrite.RealertSeconds = 60
		c.ModbusDiagnostic.RealertSeconds = 60
	})
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for i := range maxIndustrialAlertKeys {
		nm.industrialLast[fmt.Sprintf("old-%d", i)] = now.Add(-time.Hour)
	}
	nm.pruneIndustrialState(now)
	if len(nm.industrialLast) != 0 {
		t.Fatalf("expired keys kept: %d", len(nm.industrialLast))
	}

	for i := range maxIndustrialAlertKeys {
		nm.industrialLast[fmt.Sprintf("fresh-%d", i)] = now
	}
	nm.pruneIndustrialState(now)
	if len(nm.industrialLast) != 0 {
		t.Fatalf("state not reset at cap: %d", len(nm.industrialLast))
	}
}

func TestRecordIndustrial_PeersBoundedAndMostRecentLast(t *testing.T) {
	device := &models.DeviceInfo{}
	msg := industrial.Message{Protocol: "modbus", Class: industrial.ClassRead, FunctionName: "read_coils"}
	now := time.Now()
	for i := range maxIndustrialPeers + 5 {
		recordIndustrial(device, msg, fmt.Sprintf("10.0.1.%d", i), now)
	}
	recordIndustrial(device, msg, "10.0.1.10", now) // already present, moves to the end
	recordIndustrial(device, msg, "0.0.0.0", now)   // ignored

	peers := device.Industrial["modbus"].Peers
	if len(peers) != maxIndustrialPeers {
		t.Fatalf("peers = %d, want %d", len(peers), maxIndustrialPeers)
	}
	if peers[len(peers)-1] != "10.0.1.10" {
		t.Fatalf("most recent peer = %s, want 10.0.1.10", peers[len(peers)-1])
	}
}

func TestRecordIndustrial_RepairsRecordWithoutMaps(t *testing.T) {
	device := &models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"modbus": {Requests: 3}}}
	recordIndustrial(device, industrial.Message{Protocol: "modbus", Class: industrial.ClassWrite, FunctionName: "write_single_coil"}, "", time.Now())
	s := device.Industrial["modbus"]
	if s.Requests != 4 || s.Operations["write"] != 1 || s.Functions["write_single_coil"] != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestGetStats_IndustrialIsDeepCopied(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x03, 0, 0, 0, 1))

	snap := nm.GetStats()["02:00:00:00:00:01"].Industrial["modbus"]
	snap.Operations["read"] = 99
	snap.Peers[0] = "mutated"

	again := nm.GetStats()["02:00:00:00:00:01"].Industrial["modbus"]
	if again.Operations["read"] != 1 || again.Peers[0] != "10.0.0.5" {
		t.Fatalf("snapshot shares state with the monitor: %+v", again)
	}
	if cloneIndustrial(nil) != nil {
		t.Fatal("nil map should clone to nil")
	}
}

func TestIndustrialRule_Allows(t *testing.T) {
	t.Parallel()
	r := &industrialRule{allow: alerts.IndustrialRule{AllowedSources: []string{"10.0.0.0/24", "2001:db8::1"}}.SourcePrefixes()}
	for addr, want := range map[string]bool{
		"10.0.0.7":        true,
		"::ffff:10.0.0.7": true,
		"2001:db8::1":     true,
		"10.0.1.7":        false,
		"":                false,
		"not-an-address":  false,
		"2001:db8::2":     false,
	} {
		if got := r.allows(addr); got != want {
			t.Errorf("allows(%q) = %v, want %v", addr, got, want)
		}
	}
}

// s7Event builds a TCP event carrying TPKT + COTP + S7 bytes (cotp is
// everything after the TPKT header).
func s7Event(srcMAC byte, src, dst string, sport, dport uint16, cotp ...byte) *models.NetworkEvent {
	evt := modbusEvent(srcMAC, src, dst, sport, dport, 0)
	evt.L7Payload = [models.L7PayloadSize]byte{}
	n := 4 + len(cotp)
	copy(evt.L7Payload[:], append([]byte{3, 0, byte(n >> 8), byte(n)}, cotp...))
	return evt
}

func s7JobBytes(params ...byte) []byte {
	n := len(params)
	return append([]byte{0x02, 0xF0, 0x80, 0x32, 1, 0, 0, 0, 1, byte(n >> 8), byte(n), 0, 0}, params...)
}

func TestTrackEvent_S7StopAndDownloadAlert(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, s7JobBytes(0x04, 1)...))
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, s7JobBytes(0x29, 0, 0, 0, 0, 0)...))
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, s7JobBytes(0x1A, 0, 0, 0, 0, 0, 0, 0, 0)...))
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, s7JobBytes(0x05, 1)...))

	got := map[string]models.AlertEvent{}
	for _, a := range nm.GetAlerts() {
		got[a.Rule] = a
	}
	if len(got) != 3 {
		t.Fatalf("alerts = %+v, want s7_control, s7_program, s7_write", got)
	}
	if a := got[alerts.RuleS7Control]; a.Severity != "high" || a.Message != "S7comm plc_stop from 10.0.0.9 to 10.0.0.50" {
		t.Fatalf("control alert = %+v", a)
	}
	if a := got[alerts.RuleS7Program]; a.Severity != "high" || a.Message != "S7comm request_download from 10.0.0.9 to 10.0.0.50" {
		t.Fatalf("program alert = %+v", a)
	}
	if a := got[alerts.RuleS7Write]; a.Severity != "medium" {
		t.Fatalf("write alert = %+v", a)
	}
	s := nm.GetStats()["02:00:00:00:00:01"].Industrial[industrial.ProtocolS7]
	if s.Requests != 4 || s.Operations["control"] != 1 || s.Operations["program"] != 1 || s.Operations["read"] != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTrackEvent_S7ConnectRecordsRackSlot(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	cr := []byte{0x11, 0xE0, 0, 0, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2}
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, cr...))
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49153, 102, cr...))
	s := nm.GetStats()["02:00:00:00:00:01"].Industrial[industrial.ProtocolS7]
	if s.Details["rack 0 slot 2"] != 2 || s.Functions["cotp_connect"] != 2 {
		t.Fatalf("stats = %+v", s)
	}
	if len(nm.GetAlerts()) != 0 {
		t.Fatalf("a connect must not alert: %+v", nm.GetAlerts())
	}
}

func TestTrackEvent_S7PlusCountedWithoutAlert(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(s7Event(1, "10.0.0.9", "10.0.0.50", 49152, 102, 0x02, 0xF0, 0x80, 0x72, 0x03, 0x00, 0x1F))
	if s := nm.GetStats()["02:00:00:00:00:01"].Industrial[industrial.ProtocolS7Plus]; s == nil || s.Requests != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if len(nm.GetAlerts()) != 0 {
		t.Fatalf("s7comm-plus must not alert: %+v", nm.GetAlerts())
	}
}

func TestRecordIndustrial_DetailsBounded(t *testing.T) {
	device := &models.DeviceInfo{}
	msg := industrial.Message{Protocol: "s7comm", Class: industrial.ClassOther, FunctionName: "cotp_connect"}
	for i := range maxIndustrialDetails + 4 {
		msg.Detail = fmt.Sprintf("rack 0 slot %d", i)
		recordIndustrial(device, msg, "", time.Now())
	}
	msg.Detail = "rack 0 slot 0" // already known, still counted
	recordIndustrial(device, msg, "", time.Now())
	d := device.Industrial["s7comm"].Details
	if len(d) != maxIndustrialDetails || d["rack 0 slot 0"] != 2 {
		t.Fatalf("details = %v", d)
	}
}

func TestNewIndustrialRules_SkipsDisabled(t *testing.T) {
	cfg := alerts.DefaultConfig().Industrial
	cfg.S7Write.Enabled = false
	rules := newIndustrialRules(cfg)
	if _, ok := rules["s7comm|write"]; ok {
		t.Fatal("disabled rule compiled")
	}
	if r := rules["s7comm|control"]; r == nil || r.id != alerts.RuleS7Control {
		t.Fatalf("control rule = %+v", r)
	}
	if len(rules) != len(industrialRuleClasses)-1 {
		t.Fatalf("rules = %d, want %d", len(rules), len(industrialRuleClasses)-1)
	}
}

func dnp3Event(srcMAC byte, src, dst string, sport, dport uint16, control byte, destAddr, srcAddr uint16, block ...byte) *models.NetworkEvent {
	evt := modbusEvent(srcMAC, src, dst, sport, dport, 0)
	evt.Protocol = 17
	evt.EventType = models.EVENT_TYPE_UDP
	evt.L7Payload = [models.L7PayloadSize]byte{}
	h := []byte{0x05, 0x64, byte(5 + len(block)), control, byte(destAddr), byte(destAddr >> 8), byte(srcAddr), byte(srcAddr >> 8)}
	crc := dnp3TestCRC(h)
	copy(evt.L7Payload[:], append(append(h, byte(crc), byte(crc>>8)), block...))
	return evt
}

// dnp3TestCRC mirrors the decoder's CRC so frames can be built here.
func dnp3TestCRC(b []byte) uint16 {
	var crc uint16
	for _, c := range b {
		crc ^= uint16(c)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func TestTrackEvent_DNP3OperateAndRestart(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(dnp3Event(1, "10.0.0.9", "10.0.0.70", 50000, 20000, 0xC4, 10, 1, 0xC0, 0xC1, 1))
	nm.TrackEvent(dnp3Event(1, "10.0.0.9", "10.0.0.70", 50000, 20000, 0xC4, 10, 1, 0xC0, 0xC1, 5))
	nm.TrackEvent(dnp3Event(1, "10.0.0.9", "10.0.0.70", 50000, 20000, 0xC4, 10, 1, 0xC0, 0xC1, 13))
	nm.TrackEvent(dnp3Event(7, "10.0.0.70", "10.0.0.9", 20000, 50000, 0x44, 1, 10, 0xC0, 0xC1, 129, 0, 1))

	got := map[string]models.AlertEvent{}
	for _, a := range nm.GetAlerts() {
		got[a.Rule] = a
	}
	if len(got) != 2 {
		t.Fatalf("alerts = %+v", got)
	}
	if want := "DNP3 direct_operate from 10.0.0.9 to 10.0.0.70 (outstation 10)"; got[alerts.RuleDNP3Control].Message != want {
		t.Fatalf("control message = %q, want %q", got[alerts.RuleDNP3Control].Message, want)
	}
	if got[alerts.RuleDNP3Diagnostic].Message != "DNP3 cold_restart from 10.0.0.9 to 10.0.0.70 (outstation 10)" {
		t.Fatalf("diagnostic alert = %+v", got[alerts.RuleDNP3Diagnostic])
	}
	master := nm.GetStats()["02:00:00:00:00:01"].Industrial[industrial.ProtocolDNP3]
	if master.Requests != 3 || master.Details["outstation 10"] != 3 {
		t.Fatalf("master stats = %+v", master)
	}
	rtu := nm.GetStats()["02:00:00:00:00:07"].Industrial[industrial.ProtocolDNP3]
	if rtu.Responses != 1 || rtu.Exceptions != 1 {
		t.Fatalf("outstation stats = %+v", rtu)
	}
}
