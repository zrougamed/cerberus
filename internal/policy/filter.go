package policy

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// MaxFilterRules matches MAX_FILTER_RULES in ebpf/cerberus_tc.c.
const MaxFilterRules = 64

// Verdict is what a filter rule does when every matcher matches.
type Verdict string

const (
	// VerdictAccept stops evaluation and lets the packet through. It also
	// skips the blocklist sets, so it works as an exception.
	VerdictAccept Verdict = "accept"
	// VerdictDrop drops the packet when the policy is enforcing. In monitor
	// mode it is counted and stops evaluation, but the packet passes.
	VerdictDrop Verdict = "drop"
	// VerdictContinue counts (and logs) the packet and moves on.
	VerdictContinue Verdict = "continue"
)

// FilterMatch holds the matchers of a filter rule; all set fields must match.
// Field names follow bpfilter's matcher types where one exists.
type FilterMatch struct {
	Interface  string `json:"interface,omitempty"` // meta.iface
	Family     string `json:"family,omitempty"`    // meta.l3_proto: ipv4|ipv6
	Protocol   string `json:"protocol,omitempty"`  // meta.l4_proto: tcp|udp|icmp|icmpv6|<number>
	Src        string `json:"src,omitempty"`       // ip4/ip6 snet
	SrcNot     bool   `json:"src_not,omitempty"`
	Dst        string `json:"dst,omitempty"` // ip4/ip6 dnet
	DstNot     bool   `json:"dst_not,omitempty"`
	SrcMAC     string `json:"src_mac,omitempty"`
	SrcPort    string `json:"src_port,omitempty"` // "443" or "1024-65535"
	SrcPortNot bool   `json:"src_port_not,omitempty"`
	DstPort    string `json:"dst_port,omitempty"`
	DstPortNot bool   `json:"dst_port_not,omitempty"`
	// TCPFlagsAny matches when at least one flag is set; TCPFlagsAll when all
	// are (bpfilter tcp.flags any / all).
	TCPFlagsAny []string `json:"tcp_flags_any,omitempty"`
	TCPFlagsAll []string `json:"tcp_flags_all,omitempty"`
	ICMPType    *int     `json:"icmp_type,omitempty"`
	ICMPCode    *int     `json:"icmp_code,omitempty"`
}

// FilterRule is one entry of the ordered chain.
type FilterRule struct {
	ID      string      `json:"id"`
	Enabled bool        `json:"enabled"`
	Match   FilterMatch `json:"match"`
	Verdict Verdict     `json:"verdict"`
	Log     bool        `json:"log"`
	// LogEverySeconds rate-limits log events (bpfilter "log every"); 0
	// logs every match.
	LogEverySeconds float64    `json:"log_every_seconds,omitempty"`
	Comment         string     `json:"comment,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       string     `json:"created_by,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// FilterInput is what a client submits to create a filter rule.
type FilterInput struct {
	ID              string      `json:"id,omitempty"`
	Match           FilterMatch `json:"match"`
	Verdict         Verdict     `json:"verdict"`
	Log             bool        `json:"log,omitempty"`
	LogEverySeconds *float64    `json:"log_every_seconds,omitempty"` // default 1
	Comment         string      `json:"comment,omitempty"`
	TTLSeconds      int         `json:"ttl_seconds,omitempty"`
	// Position is the 0-based index to insert at; nil appends.
	Position *int `json:"position,omitempty"`
	// Disabled creates the rule switched off.
	Disabled bool `json:"disabled,omitempty"`
	// Force allows a broad drop rule, or one covering a protected address.
	Force bool `json:"force,omitempty"`
}

// Kernel codes; they must match ebpf/cerberus_tc.c.
const (
	fvAccept   uint8 = 1
	fvDrop     uint8 = 2
	fvContinue uint8 = 3

	fmICMPType uint8 = 1 << 0
	fmICMPCode uint8 = 1 << 1
	fmSMAC     uint8 = 1 << 2
	fmNotSrc   uint8 = 1 << 3
	fmNotDst   uint8 = 1 << 4
	fmNotSport uint8 = 1 << 5
	fmNotDport uint8 = 1 << 6
)

var tcpFlagBits = map[string]uint8{
	"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08,
	"ack": 0x10, "urg": 0x20, "ece": 0x40, "cwr": 0x80,
}

var protocolNumbers = map[string]uint8{"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}

// filterValue mirrors struct filter_rule (112 bytes).
type filterValue struct {
	Slot          uint32
	Verdict       uint8
	Log           uint8
	Family        uint8
	L4Proto       uint8
	Ifindex       uint32
	SportLo       uint16
	SportHi       uint16
	DportLo       uint16
	DportHi       uint16
	TCPAny        uint8
	TCPAll        uint8
	ICMPType      uint8
	ICMPCode      uint8
	MFlags        uint8
	SrcPlen       uint8
	DstPlen       uint8
	Pad0          uint8
	Src           [16]byte
	Dst           [16]byte
	SrcMask       [16]byte
	DstMask       [16]byte
	SMAC          [6]byte
	Pad1          uint16
	Pad2          uint32
	LogIntervalNs uint64
}

// compiledMatch is the parsed form of a FilterMatch.
type compiledMatch struct {
	family     uint8
	proto      uint8
	src, dst   netip.Prefix
	mac        net.HardwareAddr
	sport      [2]uint16 // [lo, hi]; hi 0 = any
	dport      [2]uint16
	tcpAny     uint8
	tcpAll     uint8
	icmpType   *uint8
	icmpCode   *uint8
	iface      string
	srcNot     bool
	dstNot     bool
	sportNot   bool
	dportNot   bool
	hasAddress bool // src, dst or MAC restricts who is affected
}

// ResolveInterface maps an interface name to its index. Replaceable in tests.
var ResolveInterface = func(name string) (uint32, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	if ifc.Index <= 0 || ifc.Index > math.MaxUint32 {
		return 0, fmt.Errorf("interface %s has index %d", name, ifc.Index)
	}
	return uint32(ifc.Index), nil
}

// compileMatch validates m. checkIface verifies the interface exists now
// (new rules); stored rules skip it so a missing NIC does not stop startup.
func compileMatch(m FilterMatch, checkIface bool) (compiledMatch, error) {
	var c compiledMatch
	switch strings.ToLower(strings.TrimSpace(m.Family)) {
	case "":
	case "ipv4", "ip4", "4":
		c.family = 4
	case "ipv6", "ip6", "6":
		c.family = 6
	default:
		return c, fmt.Errorf("unknown family %q (want ipv4|ipv6)", m.Family)
	}

	proto := strings.ToLower(strings.TrimSpace(m.Protocol))
	if proto != "" {
		if n, ok := protocolNumbers[proto]; ok {
			c.proto = n
		} else if n, err := strconv.ParseUint(proto, 0, 8); err == nil && n > 0 {
			c.proto = uint8(n)
		} else {
			return c, fmt.Errorf("unknown protocol %q (want tcp|udp|icmp|icmpv6 or 1-255)", m.Protocol)
		}
	}
	if c.proto == 1 && c.family == 6 || c.proto == 58 && c.family == 4 {
		return c, errors.New("icmp is IPv4 and icmpv6 is IPv6; the family contradicts the protocol")
	}
	// ICMP and ICMPv6 imply their IP version.
	switch c.proto {
	case 1:
		c.family = 4
	case 58:
		c.family = 6
	}

	var err error
	if c.src, err = optionalPrefix(m.Src); err != nil {
		return c, fmt.Errorf("src: %w", err)
	}
	if c.dst, err = optionalPrefix(m.Dst); err != nil {
		return c, fmt.Errorf("dst: %w", err)
	}
	for _, p := range []netip.Prefix{c.src, c.dst} {
		if !p.IsValid() {
			continue
		}
		fam := uint8(4)
		if p.Addr().Is6() {
			fam = 6
		}
		if c.family != 0 && c.family != fam {
			return c, fmt.Errorf("address %s does not match family ipv%d", p, c.family)
		}
		c.family = fam
	}
	if c.src.IsValid() && c.dst.IsValid() && c.src.Addr().Is4() != c.dst.Addr().Is4() {
		return c, errors.New("src and dst must both be IPv4 or both IPv6")
	}
	c.srcNot = m.SrcNot && c.src.IsValid()
	c.dstNot = m.DstNot && c.dst.IsValid()
	if m.SrcNot && !c.src.IsValid() || m.DstNot && !c.dst.IsValid() {
		return c, errors.New("src_not/dst_not need an address to negate")
	}

	if mac := strings.TrimSpace(m.SrcMAC); mac != "" {
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 {
			return c, fmt.Errorf("bad src_mac %q", mac)
		}
		c.mac = hw
	}

	if c.sport, err = parsePortRange(m.SrcPort); err != nil {
		return c, fmt.Errorf("src_port: %w", err)
	}
	if c.dport, err = parsePortRange(m.DstPort); err != nil {
		return c, fmt.Errorf("dst_port: %w", err)
	}
	c.sportNot = m.SrcPortNot && c.sport[1] != 0
	c.dportNot = m.DstPortNot && c.dport[1] != 0
	if m.SrcPortNot && c.sport[1] == 0 || m.DstPortNot && c.dport[1] == 0 {
		return c, errors.New("src_port_not/dst_port_not need a port to negate")
	}
	if (c.sport[1] != 0 || c.dport[1] != 0) && c.proto != 0 && c.proto != 6 && c.proto != 17 {
		return c, errors.New("ports only apply to tcp and udp")
	}

	if c.tcpAny, err = parseTCPFlags(m.TCPFlagsAny); err != nil {
		return c, err
	}
	if c.tcpAll, err = parseTCPFlags(m.TCPFlagsAll); err != nil {
		return c, err
	}
	if (c.tcpAny != 0 || c.tcpAll != 0) && c.proto != 6 {
		return c, errors.New("tcp flags need protocol tcp")
	}

	if m.ICMPType != nil || m.ICMPCode != nil {
		if c.proto != 1 && c.proto != 58 {
			return c, errors.New("icmp_type/icmp_code need protocol icmp or icmpv6")
		}
		if m.ICMPType != nil {
			t, ok := toUint8(*m.ICMPType)
			if !ok {
				return c, fmt.Errorf("icmp_type %d out of range 0-255", *m.ICMPType)
			}
			c.icmpType = &t
		}
		if m.ICMPCode != nil {
			v, ok := toUint8(*m.ICMPCode)
			if !ok {
				return c, fmt.Errorf("icmp_code %d out of range 0-255", *m.ICMPCode)
			}
			c.icmpCode = &v
		}
	}

	if name := strings.TrimSpace(m.Interface); name != "" {
		if checkIface {
			if _, err := ResolveInterface(name); err != nil {
				return c, fmt.Errorf("interface %q: %w", name, err)
			}
		}
		c.iface = name
	}
	// Negated addresses count too: "anything except the LAN" is a deliberate
	// scope. Only a rule with no address or device at all is "broad".
	c.hasAddress = c.src.IsValid() || c.dst.IsValid() || c.mac != nil
	return c, nil
}

func toUint8(v int) (uint8, bool) {
	if v < 0 || v > math.MaxUint8 {
		return 0, false
	}
	return uint8(v), true
}

func optionalPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, nil
	}
	p, err := parsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%s matches every address; leave it empty instead", p)
	}
	return p, nil
}

func parsePortRange(s string) ([2]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return [2]uint16{}, nil
	}
	loS, hiS, isRange := strings.Cut(s, "-")
	lo, err := strconv.ParseUint(strings.TrimSpace(loS), 10, 16)
	if err != nil {
		return [2]uint16{}, fmt.Errorf("bad port %q", s)
	}
	hi := lo
	if isRange {
		if hi, err = strconv.ParseUint(strings.TrimSpace(hiS), 10, 16); err != nil {
			return [2]uint16{}, fmt.Errorf("bad port range %q", s)
		}
	}
	if lo == 0 || lo > hi {
		return [2]uint16{}, fmt.Errorf("bad port range %q (1-65535, start <= end)", s)
	}
	return [2]uint16{uint16(lo), uint16(hi)}, nil
}

func parseTCPFlags(names []string) (uint8, error) {
	var bits uint8
	for _, n := range names {
		b, ok := tcpFlagBits[strings.ToLower(strings.TrimSpace(n))]
		if !ok {
			return 0, fmt.Errorf("unknown tcp flag %q (want fin, syn, rst, psh, ack, urg, ece, cwr)", n)
		}
		bits |= b
	}
	return bits, nil
}

func normalizeVerdict(v Verdict) (Verdict, error) {
	switch Verdict(strings.ToLower(strings.TrimSpace(string(v)))) {
	case VerdictAccept, "allow":
		return VerdictAccept, nil
	case VerdictDrop, "block":
		return VerdictDrop, nil
	case VerdictContinue, "count":
		return VerdictContinue, nil
	case "":
		return "", errors.New("verdict is required (accept|drop|continue)")
	default:
		return "", fmt.Errorf("unknown verdict %q (want accept|drop|continue)", v)
	}
}

// encodeFilter builds the kernel value. The interface is resolved now, so a
// rule follows an interface that was recreated with a new index on the
// next chain write.
// noInterface is an ifindex no interface has: a rule bound to an interface
// that does not exist (yet) matches nothing rather than everything.
const noInterface = math.MaxUint32

func encodeFilter(r FilterRule, c compiledMatch, slot uint32) filterValue {
	v := filterValue{Slot: slot, Family: c.family, L4Proto: c.proto}
	switch r.Verdict {
	case VerdictAccept:
		v.Verdict = fvAccept
	case VerdictDrop:
		v.Verdict = fvDrop
	default:
		v.Verdict = fvContinue
	}
	if r.Log {
		v.Log = 1
		v.LogIntervalNs = uint64(r.LogEverySeconds * float64(time.Second))
	}
	if c.iface != "" {
		v.Ifindex = noInterface
		if idx, err := ResolveInterface(c.iface); err == nil {
			v.Ifindex = idx
		}
	}
	v.SportLo, v.SportHi = c.sport[0], c.sport[1]
	v.DportLo, v.DportHi = c.dport[0], c.dport[1]
	v.TCPAny, v.TCPAll = c.tcpAny, c.tcpAll
	if c.icmpType != nil {
		v.MFlags |= fmICMPType
		v.ICMPType = *c.icmpType
	}
	if c.icmpCode != nil {
		v.MFlags |= fmICMPCode
		v.ICMPCode = *c.icmpCode
	}
	if c.mac != nil {
		v.MFlags |= fmSMAC
		copy(v.SMAC[:], c.mac)
	}
	if c.src.IsValid() {
		v.SrcPlen = prefixBits(c.src)
		v.SrcMask = prefixMask(v.SrcPlen)
		copy(v.Src[:], c.src.Addr().AsSlice())
		if c.srcNot {
			v.MFlags |= fmNotSrc
		}
	}
	if c.dst.IsValid() {
		v.DstPlen = prefixBits(c.dst)
		v.DstMask = prefixMask(v.DstPlen)
		copy(v.Dst[:], c.dst.Addr().AsSlice())
		if c.dstNot {
			v.MFlags |= fmNotDst
		}
	}
	if c.sportNot {
		v.MFlags |= fmNotSport
	}
	if c.dportNot {
		v.MFlags |= fmNotDport
	}
	return v
}

// prefixMask is the byte mask of a prefix length, so the kernel compares
// addresses without per-bit branches.
func prefixMask(bits uint8) [16]byte {
	var m [16]byte
	for i := 0; i < 16 && bits > 0; i++ {
		if bits >= 8 {
			m[i] = 0xFF
			bits -= 8
		} else {
			m[i] = byte(0xFF << (8 - bits))
			bits = 0
		}
	}
	return m
}

func prefixBits(p netip.Prefix) uint8 {
	b := p.Bits()
	if b < 0 || b > 128 {
		return 0
	}
	return uint8(b)
}

// Summary renders the matchers in bpfilter-like syntax for the console and
// audit trail, e.g. "iface eth0 tcp ip4.dnet 203.0.113.0/24 dport 443".
func (m FilterMatch) Summary() string {
	var parts []string
	add := func(s string) { parts = append(parts, s) }
	if m.Interface != "" {
		add("iface " + m.Interface)
	}
	if m.Family != "" {
		add(strings.ToLower(m.Family))
	}
	if m.Protocol != "" {
		add(strings.ToLower(m.Protocol))
	}
	neg := func(b bool) string {
		if b {
			return "not "
		}
		return ""
	}
	if m.SrcMAC != "" {
		add("smac " + strings.ToLower(m.SrcMAC))
	}
	if m.Src != "" {
		add("src " + neg(m.SrcNot) + m.Src)
	}
	if m.Dst != "" {
		add("dst " + neg(m.DstNot) + m.Dst)
	}
	if m.SrcPort != "" {
		add("sport " + neg(m.SrcPortNot) + m.SrcPort)
	}
	if m.DstPort != "" {
		add("dport " + neg(m.DstPortNot) + m.DstPort)
	}
	if len(m.TCPFlagsAny) > 0 {
		add("flags any " + strings.ToLower(strings.Join(m.TCPFlagsAny, ",")))
	}
	if len(m.TCPFlagsAll) > 0 {
		add("flags all " + strings.ToLower(strings.Join(m.TCPFlagsAll, ",")))
	}
	if m.ICMPType != nil {
		add(fmt.Sprintf("icmp type %d", *m.ICMPType))
	}
	if m.ICMPCode != nil {
		add(fmt.Sprintf("icmp code %d", *m.ICMPCode))
	}
	if len(parts) == 0 {
		return "all traffic"
	}
	return strings.Join(parts, " ")
}
