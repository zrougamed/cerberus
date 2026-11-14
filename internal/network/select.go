package network

import (
	"fmt"
	"net"
	"path"
	"strings"
)

// InterfaceFilter decides which interfaces the classifier is attached to,
// from a comma-separated list of names or shell globs (CERBERUS_INTERFACES).
// An entry starting with "!" excludes matching interfaces. When the list has
// no include entries, every up, non-loopback interface is a candidate, so
// "!docker*,!veth*" means "everything except containers".
type InterfaceFilter struct {
	include []string
	exclude []string
}

// ParseInterfaceFilter validates spec. An empty spec selects every up,
// non-loopback interface (the historical behaviour).
func ParseInterfaceFilter(spec string) (InterfaceFilter, error) {
	var f InterfaceFilter
	for raw := range strings.SplitSeq(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		negate := strings.HasPrefix(entry, "!")
		pattern := strings.TrimSpace(strings.TrimPrefix(entry, "!"))
		if pattern == "" {
			return InterfaceFilter{}, fmt.Errorf("interface filter: empty pattern in %q", entry)
		}
		// path.Match reports a malformed pattern only when it is evaluated.
		if _, err := path.Match(pattern, ""); err != nil {
			return InterfaceFilter{}, fmt.Errorf("interface filter: bad pattern %q: %w", pattern, err)
		}
		if negate {
			f.exclude = append(f.exclude, pattern)
		} else {
			f.include = append(f.include, pattern)
		}
	}
	return f, nil
}

// Select returns the interfaces to attach to, in input order. Down
// interfaces are always skipped. Loopback is skipped unless an include entry
// names it.
func (f InterfaceFilter) Select(ifaces []net.Interface) []net.Interface {
	var out []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if matchAny(f.exclude, iface.Name) {
			continue
		}
		included := matchAny(f.include, iface.Name)
		if len(f.include) > 0 && !included {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 && !included {
			continue
		}
		out = append(out, iface)
	}
	return out
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		// Patterns were validated in ParseInterfaceFilter.
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
