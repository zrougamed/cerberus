package notify

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSyslogIncludesTechniqueIDs(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	d, err := New(Config{Enabled: true, MinSeverity: "low", Syslog: SyslogConfig{Network: "udp", Address: pc.LocalAddr().String(), Tag: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Notify(Event{Kind: KindRule, Severity: "high", Title: "Rule alert: s7_program", Rule: "s7_program",
		Techniques: []string{"T0843 Program Download", "T0889 Modify Program"}})

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("syslog read: %v", err)
	}
	if msg := string(buf[:n]); !strings.Contains(msg, "techniques=T0843,T0889") {
		t.Fatalf("syslog message = %q", msg)
	}
}

func TestEventFactsTechniques(t *testing.T) {
	t.Parallel()
	facts := eventFacts(Event{Kind: KindRule, Severity: "high", Rule: "modbus_write", Techniques: []string{"T0855 Unauthorized Command Message"}})
	found := false
	for _, f := range facts {
		found = found || (f[0] == "ATT&CK for ICS" && f[1] == "T0855 Unauthorized Command Message")
	}
	if !found {
		t.Fatalf("facts = %v", facts)
	}
	for _, f := range eventFacts(Event{Kind: KindRule, Severity: "low"}) {
		if f[0] == "ATT&CK for ICS" {
			t.Fatal("empty techniques produced a fact")
		}
	}
}
