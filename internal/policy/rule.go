// Package policy is Cerberus's active-response layer: block or count traffic
// by MAC address or IPv4/IPv6 prefix in the TC classifier, in the spirit of
// bpfilter sets with per-rule counters.
//
// Rules live in user space (persisted as JSON) and are mirrored into the
// classifier's policy_* maps. A global mode decides whether "drop" rules
// really drop (enforce) or only count (monitor, the default dry run).
package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Mode is the global enforcement switch.
type Mode string

const (
	// ModeMonitor counts matches of every rule but drops nothing (dry run).
	ModeMonitor Mode = "monitor"
	// ModeEnforce makes "drop" rules drop packets in the kernel.
	ModeEnforce Mode = "enforce"
)

// Action is what a rule does to matching packets.
type Action string

const (
	// ActionDrop drops matching packets when the mode is enforce.
	ActionDrop Action = "drop"
	// ActionLog only counts matching packets, whatever the mode.
	ActionLog Action = "log"
)

// Direction says which address of a packet an IP rule is compared with.
type Direction string

const (
	DirectionSrc Direction = "src"
	DirectionDst Direction = "dst"
	DirectionAny Direction = "any"
)

// MaxRules matches MAX_POLICY_RULES in ebpf/cerberus_tc.c.
const MaxRules = 1024

// Rule is one entry of the policy. Exactly one of MAC and CIDR is set.
type Rule struct {
	ID        string     `json:"id"`
	Action    Action     `json:"action"`
	MAC       string     `json:"mac,omitempty"`
	CIDR      string     `json:"cidr,omitempty"`
	Direction Direction  `json:"direction,omitempty"` // IP rules only
	Comment   string     `json:"comment,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RuleInput is what a client submits to create a rule.
type RuleInput struct {
	ID        string    `json:"id,omitempty"`
	Action    Action    `json:"action"`
	MAC       string    `json:"mac,omitempty"`
	CIDR      string    `json:"cidr,omitempty"`
	Direction Direction `json:"direction,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	// TTLSeconds > 0 makes the rule expire automatically (temporary block).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Force allows a rule that covers a protected address (the gateway or
	// one of this host's own addresses).
	Force bool `json:"force,omitempty"`
}

// ErrProtected is returned when a rule could cut off this host or the
// gateway (or matches every host) and the request did not set force.
var ErrProtected = errors.New("needs confirmation")

var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const (
	maxCommentLen = 256
	maxTTL        = 365 * 24 * 3600
)

// target is the parsed match of a rule.
type target struct {
	mac    net.HardwareAddr // set for MAC rules
	prefix netip.Prefix     // set for IP rules
}

func (t target) key() string {
	if t.mac != nil {
		return "mac:" + t.mac.String()
	}
	return "ip:" + t.prefix.String()
}

// normalize validates in and returns the rule and its parsed target.
// ID, CreatedAt and ExpiresAt are filled in by the engine.
func normalize(in RuleInput) (Rule, target, error) {
	r := Rule{
		ID:        strings.TrimSpace(in.ID),
		Action:    Action(strings.ToLower(strings.TrimSpace(string(in.Action)))),
		Direction: Direction(strings.ToLower(strings.TrimSpace(string(in.Direction)))),
		Comment:   strings.TrimSpace(in.Comment),
	}
	if r.ID != "" && !ruleIDPattern.MatchString(r.ID) {
		return Rule{}, target{}, fmt.Errorf("id %q: use 1-64 letters, digits, '_' or '-'", r.ID)
	}
	switch r.Action {
	case ActionDrop, ActionLog:
	case "":
		return Rule{}, target{}, errors.New("action is required (drop|log)")
	default:
		return Rule{}, target{}, fmt.Errorf("unknown action %q (want drop|log)", r.Action)
	}
	if len(r.Comment) > maxCommentLen {
		return Rule{}, target{}, fmt.Errorf("comment longer than %d bytes", maxCommentLen)
	}
	if in.TTLSeconds < 0 || in.TTLSeconds > maxTTL {
		return Rule{}, target{}, fmt.Errorf("ttl_seconds must be between 0 and %d", maxTTL)
	}

	mac, cidr := strings.TrimSpace(in.MAC), strings.TrimSpace(in.CIDR)
	var t target
	switch {
	case mac != "" && cidr != "":
		return Rule{}, target{}, errors.New("set either mac or cidr, not both")
	case mac != "":
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 {
			return Rule{}, target{}, fmt.Errorf("bad mac %q", mac)
		}
		if hw[0]&0x01 != 0 {
			return Rule{}, target{}, fmt.Errorf("mac %s is multicast/broadcast", hw)
		}
		if r.Direction != "" && r.Direction != DirectionSrc {
			return Rule{}, target{}, errors.New("mac rules match the source address only; omit direction")
		}
		r.MAC, r.Direction = hw.String(), ""
		t.mac = hw
	case cidr != "":
		p, err := parsePrefix(cidr)
		if err != nil {
			return Rule{}, target{}, err
		}
		if p.Bits() == 0 {
			return Rule{}, target{}, fmt.Errorf("cidr %s matches every address; refusing", p)
		}
		if r.Direction == "" {
			r.Direction = DirectionAny
		}
		switch r.Direction {
		case DirectionSrc, DirectionDst, DirectionAny:
		default:
			return Rule{}, target{}, fmt.Errorf("unknown direction %q (want src|dst|any)", r.Direction)
		}
		r.CIDR = p.String()
		t.prefix = p
	default:
		return Rule{}, target{}, errors.New("mac or cidr is required")
	}
	return r, t, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("bad cidr %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("bad cidr %q: IPv4-mapped prefix shorter than /96", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// targetOf re-parses a stored rule (used when loading the state file).
func targetOf(r Rule) (target, error) {
	_, t, err := normalize(RuleInput{
		ID: r.ID, Action: r.Action, MAC: r.MAC, CIDR: r.CIDR, Direction: r.Direction,
	})
	return t, err
}
