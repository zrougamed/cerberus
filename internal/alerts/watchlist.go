package alerts

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Watchlist directions: which side of a packet is compared with the list.
const (
	DirectionAny = "any"
	DirectionSrc = "src"
	DirectionDst = "dst"
)

// Watchlist is a named set of IPv4/IPv6 prefixes. Traffic to or from a
// listed address raises a rule alert "watchlist:<id>" and bumps a per-list
// hit counter, the passive equivalent of a bpfilter "(ip4.snet) in set" rule
// with a counter and a rate-limited log.
type Watchlist struct {
	ID string `yaml:"id" json:"id"`
	// Enabled defaults to true when omitted from the file.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// CIDRs holds prefixes ("203.0.113.0/24", "2001:db8::/32") or single
	// addresses, which are treated as /32 or /128.
	CIDRs     []string `yaml:"cidrs" json:"cidrs"`
	Direction string   `yaml:"direction" json:"direction"`
	Severity  string   `yaml:"severity" json:"severity"`
	Message   string   `yaml:"message" json:"message"`
	// RealertSeconds is the minimum gap between two alerts for the same
	// device and remote address. Hits are still counted in between.
	RealertSeconds int `yaml:"realert_seconds" json:"realert_seconds"`
}

type watchlistOverlay struct {
	ID             string   `yaml:"id" json:"id"`
	Enabled        *bool    `yaml:"enabled" json:"enabled"`
	CIDRs          []string `yaml:"cidrs" json:"cidrs"`
	Direction      string   `yaml:"direction" json:"direction"`
	Severity       string   `yaml:"severity" json:"severity"`
	Message        string   `yaml:"message" json:"message"`
	RealertSeconds *int     `yaml:"realert_seconds" json:"realert_seconds"`
}

const defaultRealertSeconds = 600

// toWatchlist applies defaults for omitted fields.
func (o watchlistOverlay) toWatchlist() Watchlist {
	w := Watchlist{
		ID:             strings.TrimSpace(o.ID),
		Enabled:        true,
		CIDRs:          o.CIDRs,
		Direction:      strings.ToLower(strings.TrimSpace(o.Direction)),
		Severity:       strings.ToLower(strings.TrimSpace(o.Severity)),
		Message:        o.Message,
		RealertSeconds: defaultRealertSeconds,
	}
	if o.Enabled != nil {
		w.Enabled = *o.Enabled
	}
	if w.Direction == "" {
		w.Direction = DirectionAny
	}
	if w.Severity == "" {
		w.Severity = "high"
	}
	if o.RealertSeconds != nil {
		w.RealertSeconds = *o.RealertSeconds
	}
	return w
}

// Same alphabet as bpfilter set names.
var watchlistIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// maxWatchlistPrefixes bounds the in-memory matcher; larger feeds belong in
// a kernel LPM map, not a linear scan.
const maxWatchlistPrefixes = 10000

func validateWatchlists(lists []Watchlist) error {
	seen := make(map[string]struct{}, len(lists))
	total := 0
	for i, w := range lists {
		if !watchlistIDPattern.MatchString(w.ID) {
			return fmt.Errorf("watchlists[%d]: id %q must be non-empty and use only letters, digits, '_' or '-'", i, w.ID)
		}
		if _, dup := seen[w.ID]; dup {
			return fmt.Errorf("watchlists: duplicate id %q", w.ID)
		}
		seen[w.ID] = struct{}{}
		if !w.Enabled {
			continue
		}
		if len(w.CIDRs) == 0 {
			return fmt.Errorf("watchlist %q: cidrs must not be empty", w.ID)
		}
		for _, c := range w.CIDRs {
			if _, err := parsePrefix(c); err != nil {
				return fmt.Errorf("watchlist %q: %w", w.ID, err)
			}
		}
		total += len(w.CIDRs)
		switch w.Direction {
		case DirectionAny, DirectionSrc, DirectionDst:
		default:
			return fmt.Errorf("watchlist %q: unknown direction %q (want any|src|dst)", w.ID, w.Direction)
		}
		if !validSeverity(w.Severity) {
			return fmt.Errorf("watchlist %q: unknown severity %q (want low|medium|high)", w.ID, w.Severity)
		}
		if w.RealertSeconds < 0 {
			return fmt.Errorf("watchlist %q: realert_seconds must be >= 0", w.ID)
		}
	}
	if total > maxWatchlistPrefixes {
		return fmt.Errorf("watchlists: %d prefixes exceeds the limit of %d", total, maxWatchlistPrefixes)
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("bad cidr %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad address %q: %w", s, err)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// WatchlistHit is one list matched by one packet.
type WatchlistHit struct {
	List   Watchlist
	Remote netip.Addr // the listed address (src or dst)
}

// WatchlistMatcher checks packet addresses against the enabled watchlists.
type WatchlistMatcher struct {
	lists    []Watchlist
	prefixes [][]netip.Prefix
}

// NewWatchlistMatcher compiles validated watchlists. Disabled lists are
// dropped.
func NewWatchlistMatcher(lists []Watchlist) (*WatchlistMatcher, error) {
	if err := validateWatchlists(lists); err != nil {
		return nil, err
	}
	m := &WatchlistMatcher{}
	for _, w := range lists {
		if !w.Enabled {
			continue
		}
		ps := make([]netip.Prefix, 0, len(w.CIDRs))
		for _, c := range w.CIDRs {
			p, _ := parsePrefix(c) // validated above
			ps = append(ps, p)
		}
		m.lists = append(m.lists, w)
		m.prefixes = append(m.prefixes, ps)
	}
	return m, nil
}

// Empty reports whether no list is active, so callers can skip address
// parsing on the hot path.
func (m *WatchlistMatcher) Empty() bool {
	return m == nil || len(m.lists) == 0
}

// Match returns one hit per list whose prefixes contain src (for "src" and
// "any") or dst (for "dst" and "any"). With "any", src is checked first.
func (m *WatchlistMatcher) Match(src, dst netip.Addr) []WatchlistHit {
	if m.Empty() {
		return nil
	}
	src, dst = src.Unmap(), dst.Unmap()
	var hits []WatchlistHit
	for i, w := range m.lists {
		var candidates []netip.Addr
		switch w.Direction {
		case DirectionSrc:
			candidates = []netip.Addr{src}
		case DirectionDst:
			candidates = []netip.Addr{dst}
		default:
			candidates = []netip.Addr{src, dst}
		}
		if addr, ok := firstContained(m.prefixes[i], candidates); ok {
			hits = append(hits, WatchlistHit{List: w, Remote: addr})
		}
	}
	return hits
}

func firstContained(prefixes []netip.Prefix, addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		for _, p := range prefixes {
			if p.Contains(a) {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}
