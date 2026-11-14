package policy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// logEvent mirrors struct filter_log_event (72 bytes).
type logEvent struct {
	TsNs     uint64
	Slot     uint32
	Ifindex  uint32
	PktLen   uint32
	Verdict  uint8
	Enforced uint8
	Family   uint8
	Proto    uint8
	Sport    uint16
	Dport    uint16
	TCPFlags uint8
	ICMPType uint8
	ICMPCode uint8
	Pad      uint8
	Src      [16]byte
	Dst      [16]byte
	SMAC     [6]byte
	Pad1     uint16
}

// FilterLogEntry is one packet logged by a filter rule with "log" set.
type FilterLogEntry struct {
	At        time.Time `json:"at"`
	RuleID    string    `json:"rule_id"`
	Verdict   Verdict   `json:"verdict"`
	Dropped   bool      `json:"dropped"`
	Interface string    `json:"interface,omitempty"`
	Family    string    `json:"family,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Src       string    `json:"src,omitempty"`
	Dst       string    `json:"dst,omitempty"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	TCPFlags  string    `json:"tcp_flags,omitempty"`
	ICMPType  *int      `json:"icmp_type,omitempty"`
	ICMPCode  *int      `json:"icmp_code,omitempty"`
	SrcMAC    string    `json:"src_mac"`
	Length    uint32    `json:"length"`
}

// InterfaceName maps an ifindex to a name for log entries. Replaceable in
// tests.
var InterfaceName = func(idx uint32) string {
	if ifc, err := net.InterfaceByIndex(int(idx)); err == nil {
		return ifc.Name
	}
	return strconv.FormatUint(uint64(idx), 10)
}

var protocolNames = map[uint8]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

func decodeLogEvent(raw []byte) (logEvent, error) {
	var e logEvent
	if len(raw) < binary.Size(e) {
		return e, fmt.Errorf("filter log event: %d bytes, want %d", len(raw), binary.Size(e))
	}
	err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e)
	return e, err
}

func (e logEvent) entry(at time.Time, ruleID string) FilterLogEntry {
	out := FilterLogEntry{
		At:      at,
		RuleID:  ruleID,
		Dropped: e.Enforced == 1,
		Length:  e.PktLen,
		SrcMAC:  net.HardwareAddr(e.SMAC[:]).String(),
	}
	switch e.Verdict {
	case fvAccept:
		out.Verdict = VerdictAccept
	case fvDrop:
		out.Verdict = VerdictDrop
	default:
		out.Verdict = VerdictContinue
	}
	if e.Ifindex != 0 {
		out.Interface = InterfaceName(e.Ifindex)
	}
	switch e.Family {
	case 4:
		out.Family = "ipv4"
		out.Src = netip.AddrFrom4([4]byte(e.Src[:4])).String()
		out.Dst = netip.AddrFrom4([4]byte(e.Dst[:4])).String()
	case 6:
		out.Family = "ipv6"
		out.Src = netip.AddrFrom16(e.Src).String()
		out.Dst = netip.AddrFrom16(e.Dst).String()
	}
	if e.Family != 0 {
		if name, ok := protocolNames[e.Proto]; ok {
			out.Protocol = name
		} else {
			out.Protocol = strconv.Itoa(int(e.Proto))
		}
	}
	switch e.Proto {
	case 6, 17:
		out.SrcPort, out.DstPort = e.Sport, e.Dport
		if e.Proto == 6 {
			out.TCPFlags = tcpFlagString(e.TCPFlags)
		}
	case 1, 58:
		t, c := int(e.ICMPType), int(e.ICMPCode)
		out.ICMPType, out.ICMPCode = &t, &c
	}
	return out
}

func tcpFlagString(bits uint8) string {
	var names []string
	for _, n := range []string{"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"} {
		if bits&tcpFlagBits[n] != 0 {
			names = append(names, n)
		}
	}
	return strings.Join(names, ",")
}
