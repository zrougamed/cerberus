package policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/zrougamed/cerberus/internal/models"
)

// HostMatch selects which telemetry a hostname rule compares against.
type HostMatch string

const (
	HostMatchDNS HostMatch = "dns"
	HostMatchSNI HostMatch = "sni"
	HostMatchAny HostMatch = "any"
)

const maxHostnameLen = 253

// HostDevice is the telemetry slice SyncHostnames needs from the monitor.
type HostDevice struct {
	MAC               string
	DNSDomains        map[string]int
	TLSSNIs           map[string]int
	CorrelatedDomains map[string]int
}

// DevicesFromInfo adapts monitor GetStats() values for hostname sync.
func DevicesFromInfo(devs map[string]*models.DeviceInfo) []HostDevice {
	out := make([]HostDevice, 0, len(devs))
	for _, d := range devs {
		if d == nil {
			continue
		}
		out = append(out, HostDevice{
			MAC:               d.MAC,
			DNSDomains:        d.DNSDomains,
			TLSSNIs:           d.TLSSNIs,
			CorrelatedDomains: d.CorrelatedDomains,
		})
	}
	return out
}

func normalizeHostname(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("hostname is required")
	}
	if len(s) > maxHostnameLen {
		return "", fmt.Errorf("hostname longer than %d bytes", maxHostnameLen)
	}
	if strings.ContainsAny(s, " \t\r\n/") {
		return "", fmt.Errorf("hostname %q has invalid characters", s)
	}
	// Allow exact names and a single leading "*." wildcard.
	rest := s
	if strings.HasPrefix(s, "*.") {
		rest = s[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return "", fmt.Errorf("bad hostname wildcard %q", s)
		}
	} else if strings.Contains(s, "*") {
		return "", fmt.Errorf("only a leading *. wildcard is supported")
	}
	for _, label := range strings.Split(rest, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("bad hostname label in %q", s)
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(label)-1)
			if !ok {
				return "", fmt.Errorf("bad hostname label %q", label)
			}
		}
	}
	return s, nil
}

// HostnameMatches reports whether observed equals or falls under pattern.
// pattern may be an FQDN or a single-level wildcard like "*.evil.com".
func HostnameMatches(pattern, observed string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	observed = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(observed), "."))
	if pattern == "" || observed == "" {
		return false
	}
	if pattern == observed {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".evil.com"
		if !strings.HasSuffix(observed, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(observed, suffix)
		return prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}

func hostMatchesDevice(r Rule, d HostDevice) bool {
	if r.Hostname == "" {
		return false
	}
	match := HostMatch(r.HostMatch)
	if match == "" {
		match = HostMatchAny
	}
	checkDNS := match == HostMatchDNS || match == HostMatchAny
	checkSNI := match == HostMatchSNI || match == HostMatchAny
	if checkDNS {
		for name := range d.DNSDomains {
			if HostnameMatches(r.Hostname, name) {
				return true
			}
		}
		for name := range d.CorrelatedDomains {
			if HostnameMatches(r.Hostname, name) {
				return true
			}
		}
	}
	if checkSNI {
		for name := range d.TLSSNIs {
			if HostnameMatches(r.Hostname, name) {
				return true
			}
		}
	}
	return false
}

func derivedRuleID(parentID, mac string) string {
	hw, err := net.ParseMAC(mac)
	compact := strings.ReplaceAll(mac, ":", "")
	if err == nil {
		compact = fmt.Sprintf("%x", []byte(hw))
	}
	id := "h-" + parentID + "-" + compact
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}

// SyncHostnames installs or removes derived MAC quarantine rules for devices
// whose DNS / SNI telemetry matches a hostname blocklist entry. Derived rules
// are ephemeral (not written to the state file).
func (e *Engine) SyncHostnames(devices []HostDevice) {
	e.mu.Lock()
	defer e.mu.Unlock()

	desired := make(map[string]map[string]Rule) // parentID -> mac -> parent rule
	for _, en := range e.rules {
		r := en.rule
		if r.Hostname == "" || r.ParentID != "" {
			continue
		}
		want := make(map[string]Rule)
		for _, d := range devices {
			if d.MAC == "" || !hostMatchesDevice(r, d) {
				continue
			}
			want[d.MAC] = r
		}
		desired[r.ID] = want
	}

	// Drop stale derived rules.
	for id, en := range e.rules {
		parent := en.rule.ParentID
		if parent == "" {
			continue
		}
		want := desired[parent]
		if want == nil {
			_ = e.removeDerivedLocked(id)
			continue
		}
		if _, ok := want[en.rule.MAC]; !ok {
			_ = e.removeDerivedLocked(id)
		}
	}

	// Install missing derived MAC rules.
	for parentID, macs := range desired {
		parent := e.rules[parentID]
		if parent == nil {
			continue
		}
		for mac, src := range macs {
			childID := derivedRuleID(parentID, mac)
			if e.rules[childID] != nil {
				continue
			}
			hw, err := net.ParseMAC(mac)
			if err != nil || len(hw) != 6 || hw[0]&0x01 != 0 {
				continue
			}
			if e.protectedHit(target{mac: hw}) != "" {
				continue // never auto-quarantine gateway/self
			}
			r := Rule{
				ID:        childID,
				Action:    src.Action,
				MAC:       hw.String(),
				Comment:   "auto: " + string(src.HostMatch) + " " + src.Hostname,
				CreatedAt: e.opts.Now().UTC(),
				CreatedBy: "hostname-sync",
				ExpiresAt: src.ExpiresAt,
				ParentID:  parentID,
				Hostname:  src.Hostname,
				HostMatch: src.HostMatch,
			}
			t := target{mac: hw}
			if err := e.insertLocked(r, t); err != nil {
				continue
			}
			en := e.rules[r.ID]
			if e.kernel != nil {
				if err := e.kernel.ResetCounter(en.slot); err != nil {
					e.removeLocked(r.ID)
					continue
				}
				if err := put(e.kernel, en); err != nil {
					e.removeLocked(r.ID)
					continue
				}
			}
		}
	}
}

func (e *Engine) removeDerivedLocked(id string) error {
	en := e.rules[id]
	if en == nil {
		return ErrNotFound
	}
	if e.kernel != nil {
		if err := del(e.kernel, en); err != nil {
			return err
		}
	}
	e.removeLocked(id)
	return nil
}
