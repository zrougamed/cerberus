package notify

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/zrougamed/cerberus/internal/version"
)

// Syslog message formats.
const (
	SyslogFormatText = "text"
	SyslogFormatCEF  = "cef"
	SyslogFormatLEEF = "leef"
)

const productName = "Cerberus"

// formatEvent renders e as one syslog message body in the given format.
func formatEvent(e Event, format string) string {
	switch format {
	case SyslogFormatCEF:
		return formatCEF(e)
	case SyslogFormatLEEF:
		return formatLEEF(e)
	default:
		return formatText(e)
	}
}

// formatText is the original key=value line.
func formatText(e Event) string {
	msg := fmt.Sprintf("cerberus kind=%s severity=%s title=%q message=%q", e.Kind, e.Severity, e.Title, e.Message)
	if e.DeviceMAC != "" {
		msg += fmt.Sprintf(" mac=%s", e.DeviceMAC)
	}
	if e.DeviceIP != "" {
		msg += fmt.Sprintf(" ip=%s", e.DeviceIP)
	}
	if e.Rule != "" {
		msg += fmt.Sprintf(" rule=%s", e.Rule)
	}
	if e.Score > 0 {
		msg += fmt.Sprintf(" score=%.2f", e.Score)
	}
	if ids := techniqueIDs(e.Techniques); ids != "" {
		msg += " techniques=" + ids
	}
	return msg
}

func techniqueIDs(ts []string) string {
	ids := make([]string, 0, len(ts))
	for _, t := range ts {
		id, _, _ := strings.Cut(t, " ")
		ids = append(ids, id)
	}
	return strings.Join(ids, ",")
}

// eventID names the event for SIEM correlation: the rule, else the kind.
func eventID(e Event) string {
	if e.Rule != "" {
		return e.Rule
	}
	return e.Kind
}

// siemSeverity maps low/medium/high onto the 0-10 scale CEF and LEEF use.
func siemSeverity(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return 9
	case "medium":
		return 6
	case "low":
		return 3
	}
	return 1
}

// cefHeader escapes a CEF header field: backslash and pipe, and newlines
// (not allowed in the header) become spaces.
var cefHeader = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ")

// cefValue escapes a CEF extension value: backslash, equals sign and line
// breaks.
var cefValue = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`)

// formatCEF renders ArcSight Common Event Format version 0.
func formatCEF(e Event) string {
	var ext []string
	add := func(k, v string) {
		if v != "" {
			ext = append(ext, k+"="+cefValue.Replace(v))
		}
	}
	if !e.ObservedAt.IsZero() {
		add("rt", strconv.FormatInt(e.ObservedAt.UnixMilli(), 10))
	}
	add("cat", e.Kind)
	add("msg", e.Message)
	if a, err := netip.ParseAddr(e.DeviceIP); err == nil {
		if a.Is4() {
			add("src", a.String())
		} else {
			add("c6a2", a.String()) // CEF's IPv6 source address key
			add("c6a2Label", "Source IPv6 Address")
		}
	}
	add("smac", e.DeviceMAC)
	if e.Rule != "" {
		add("cs1Label", "Rule")
		add("cs1", e.Rule)
	}
	if e.Vendor != "" {
		add("cs2Label", "Vendor")
		add("cs2", e.Vendor)
	}
	if len(e.Techniques) > 0 {
		add("cs3Label", "ATT&CK for ICS")
		add("cs3", strings.Join(e.Techniques, ", "))
	}
	if e.Score > 0 {
		add("cfp1Label", "Anomaly score")
		add("cfp1", strconv.FormatFloat(e.Score, 'f', 2, 64))
	}
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		cefHeader.Replace(productName), cefHeader.Replace(productName), cefHeader.Replace(version.Get().Commit),
		cefHeader.Replace(eventID(e)), cefHeader.Replace(e.Title), siemSeverity(e.Severity), strings.Join(ext, " "))
}

// leefHeader drops what LEEF header fields cannot hold.
var leefHeader = strings.NewReplacer("|", " ", "\r", " ", "\n", " ", "\t", " ")

// leefValue keeps the tab delimiter and line breaks out of values.
var leefValue = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")

const leefTimeFormat = "2006-01-02T15:04:05.000Z07:00"

// formatLEEF renders IBM QRadar Log Event Extended Format 2.0 with the
// default tab delimiter.
func formatLEEF(e Event) string {
	var attrs []string
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, k+"="+leefValue.Replace(v))
		}
	}
	if !e.ObservedAt.IsZero() {
		add("devTime", e.ObservedAt.UTC().Format(leefTimeFormat))
		add("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
	}
	add("cat", e.Kind)
	add("sev", strconv.Itoa(siemSeverity(e.Severity)))
	if a, err := netip.ParseAddr(e.DeviceIP); err == nil {
		add("src", a.String())
	}
	add("srcMAC", e.DeviceMAC)
	add("msg", e.Message)
	add("rule", e.Rule)
	add("vendor", e.Vendor)
	add("techniques", strings.Join(e.Techniques, ", "))
	if e.Score > 0 {
		add("score", strconv.FormatFloat(e.Score, 'f', 2, 64))
	}
	return fmt.Sprintf("LEEF:2.0|%s|%s|%s|%s|%s",
		leefHeader.Replace(productName), leefHeader.Replace(productName), leefHeader.Replace(version.Get().Commit),
		leefHeader.Replace(eventID(e)), strings.Join(attrs, "\t"))
}
