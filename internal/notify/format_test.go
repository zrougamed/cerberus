package notify

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

var sampleEvent = Event{
	Kind:       KindRule,
	Severity:   "high",
	Title:      "Rule alert: s7_program",
	Message:    "S7comm request_download from 10.20.0.30 to 10.20.0.60",
	DeviceMAC:  "00:1b:1b:00:00:1e",
	DeviceIP:   "10.20.0.30",
	Vendor:     "Siemens AG",
	Rule:       "s7_program",
	Techniques: []string{"T0843 Program Download", "T0889 Modify Program"},
	ObservedAt: time.Date(2026, 11, 15, 12, 30, 0, 123000000, time.UTC),
}

func TestFormatCEF(t *testing.T) {
	t.Parallel()
	got := formatCEF(sampleEvent)
	rt := strconv.FormatInt(sampleEvent.ObservedAt.UnixMilli(), 10)
	want := "CEF:0|Cerberus|Cerberus|unknown|s7_program|Rule alert: s7_program|9|rt=" + rt + " cat=rule " +
		"msg=S7comm request_download from 10.20.0.30 to 10.20.0.60 src=10.20.0.30 smac=00:1b:1b:00:00:1e " +
		"cs1Label=Rule cs1=s7_program cs2Label=Vendor cs2=Siemens AG cs3Label=ATT&CK for ICS cs3=T0843 Program Download, T0889 Modify Program"
	if got != want {
		t.Fatalf("CEF\n got %s\nwant %s", got, want)
	}
}

func TestFormatCEF_EscapingAndOptionalFields(t *testing.T) {
	t.Parallel()
	e := Event{Kind: KindAnomaly, Severity: "medium", Title: "pipe | and \\ back\nslash", Message: "a=b \\ c\r\nnext",
		DeviceIP: "2001:db8::5", Score: 4.256}
	got := formatCEF(e)
	for _, want := range []string{
		`|anomaly|pipe \| and \\ back slash|6|`,
		`msg=a\=b \\ c\r\nnext`,
		`c6a2=2001:db8::5 c6a2Label=Source IPv6 Address`,
		`cfp1Label=Anomaly score cfp1=4.26`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CEF missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "rt=") || strings.Contains(got, "smac=") {
		t.Errorf("empty fields rendered: %s", got)
	}
}

func TestFormatLEEF(t *testing.T) {
	t.Parallel()
	got := formatLEEF(sampleEvent)
	want := "LEEF:2.0|Cerberus|Cerberus|unknown|s7_program|" + strings.Join([]string{
		"devTime=2026-11-15T12:30:00.123Z", "devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "cat=rule", "sev=9",
		"src=10.20.0.30", "srcMAC=00:1b:1b:00:00:1e", "msg=S7comm request_download from 10.20.0.30 to 10.20.0.60",
		"rule=s7_program", "vendor=Siemens AG", "techniques=T0843 Program Download, T0889 Modify Program",
	}, "\t")
	if got != want {
		t.Fatalf("LEEF\n got %q\nwant %q", got, want)
	}
	e := Event{Kind: KindNewDevice, Severity: "low", Title: "x", Message: "tab\there\nline", Score: 1.5}
	got = formatLEEF(e)
	if !strings.Contains(got, "|new_device|cat=new_device\tsev=3\tmsg=tab here line\tscore=1.50") {
		t.Fatalf("LEEF = %q", got)
	}
}

func TestFormatText_UnchangedAndDispatch(t *testing.T) {
	t.Parallel()
	want := `cerberus kind=rule severity=high title="Rule alert: s7_program" message="S7comm request_download from 10.20.0.30 to 10.20.0.60" mac=00:1b:1b:00:00:1e ip=10.20.0.30 rule=s7_program techniques=T0843,T0889`
	if got := formatEvent(sampleEvent, ""); got != want {
		t.Fatalf("text\n got %s\nwant %s", got, want)
	}
	if !strings.HasPrefix(formatEvent(sampleEvent, SyslogFormatCEF), "CEF:0|") || !strings.HasPrefix(formatEvent(sampleEvent, SyslogFormatLEEF), "LEEF:2.0|") {
		t.Fatal("format dispatch")
	}
	if got := formatText(Event{Kind: KindAnomaly, Severity: "low", Score: 3.5}); !strings.Contains(got, "score=3.50") {
		t.Fatalf("score missing: %s", got)
	}
	if siemSeverity("unknown") != 1 {
		t.Fatal("unknown severity")
	}
}

// splitCEFHeader splits on pipes not preceded by a backslash escape.
func splitCEFHeader(s string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == '|' && len(parts) < 7:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(parts, cur.String())
}

func FuzzFormatSIEM(f *testing.F) {
	f.Add("Rule | alert", "msg = with \\ and\nnewline", "rule:x", "Vendor\tInc")
	f.Fuzz(func(t *testing.T, title, msg, rule, vendor string) {
		e := Event{Kind: KindRule, Severity: "high", Title: title, Message: msg, Rule: rule, Vendor: vendor}
		cef := formatCEF(e)
		if strings.ContainsAny(cef, "\r\n") {
			t.Fatalf("CEF contains a raw line break: %q", cef)
		}
		if parts := splitCEFHeader(cef); len(parts) != 8 {
			t.Fatalf("CEF header has %d fields: %q", len(parts), cef)
		}
		leef := formatLEEF(e)
		if strings.ContainsAny(leef, "\r\n") {
			t.Fatalf("LEEF contains a raw line break: %q", leef)
		}
		head, attrs, _ := strings.Cut(leef, "|"+leefHeader.Replace(eventID(e))+"|")
		if strings.Count(head, "|") != 3 {
			t.Fatalf("LEEF header broken: %q", leef)
		}
		for _, a := range strings.Split(attrs, "\t") {
			if a != "" && !strings.Contains(a, "=") {
				t.Fatalf("LEEF attribute without key: %q in %q", a, leef)
			}
		}
	})
}
