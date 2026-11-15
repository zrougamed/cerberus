package alerts

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rule ids raised by zone and conduit checks.
const (
	RuleZoneNoConduit = "zone_no_conduit"
	RuleZoneLevelSkip = "zone_level_skip"
)

const (
	maxZoneLevel    = 5 // Purdue levels 0 (process) to 5 (enterprise)
	maxZonePrefixes = 1000
)

// Zone is a named set of networks at one Purdue level.
type Zone struct {
	ID    string   `yaml:"id" json:"id"`
	Name  string   `yaml:"name" json:"name"`
	Level int      `yaml:"level" json:"level"`
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
	// Industrial zones carry control traffic. A dropped packet there can
	// stop a process, so they are watch-only unless Enforce is set.
	Industrial bool `yaml:"industrial" json:"industrial"`
	// Enforce allows policy drop rules that cover this zone. Defaults to
	// true for ordinary zones and false for industrial ones.
	Enforce bool `yaml:"enforce" json:"enforce"`
}

// Conduit allows traffic from one zone to another, optionally only to some
// ports. Replies (from the listed ports back to the client) are always
// allowed; Bidirectional also lets the "to" side open connections.
type Conduit struct {
	From          string `yaml:"from" json:"from"`
	To            string `yaml:"to" json:"to"`
	Ports         []int  `yaml:"ports" json:"ports"`
	Bidirectional bool   `yaml:"bidirectional" json:"bidirectional"`
}

// ZoneRule configures one zone alert.
type ZoneRule struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Severity       string `yaml:"severity" json:"severity"`
	RealertSeconds int    `yaml:"realert_seconds" json:"realert_seconds"`
}

// SegmentationConfig holds zones, conduits and the alerts on traffic that
// crosses a zone boundary without a conduit.
type SegmentationConfig struct {
	Zones     []Zone    `yaml:"zones" json:"zones"`
	Conduits  []Conduit `yaml:"conduits" json:"conduits"`
	NoConduit ZoneRule  `yaml:"no_conduit" json:"no_conduit"`
	LevelSkip ZoneRule  `yaml:"level_skip" json:"level_skip"`
}

type zoneOverlay struct {
	ID         string   `yaml:"id" json:"id"`
	Name       string   `yaml:"name" json:"name"`
	Level      int      `yaml:"level" json:"level"`
	CIDRs      []string `yaml:"cidrs" json:"cidrs"`
	Industrial bool     `yaml:"industrial" json:"industrial"`
	Enforce    *bool    `yaml:"enforce" json:"enforce"`
}

type zoneRuleOverlay struct {
	Enabled        *bool   `yaml:"enabled" json:"enabled"`
	Severity       *string `yaml:"severity" json:"severity"`
	RealertSeconds *int    `yaml:"realert_seconds" json:"realert_seconds"`
}

type segmentationOverlay struct {
	Zones     []zoneOverlay    `yaml:"zones" json:"zones"`
	Conduits  []Conduit        `yaml:"conduits" json:"conduits"`
	NoConduit *zoneRuleOverlay `yaml:"no_conduit" json:"no_conduit"`
	LevelSkip *zoneRuleOverlay `yaml:"level_skip" json:"level_skip"`
}

func defaultSegmentation() SegmentationConfig {
	return SegmentationConfig{
		NoConduit: ZoneRule{Enabled: true, Severity: "medium", RealertSeconds: defaultIndustrialRealertSeconds},
		// Skipping a level (enterprise straight to control) is what
		// segmentation exists to prevent.
		LevelSkip: ZoneRule{Enabled: true, Severity: "high", RealertSeconds: defaultIndustrialRealertSeconds},
	}
}

func mergeSegmentation(dst *SegmentationConfig, src *segmentationOverlay) {
	if src == nil {
		return
	}
	if src.Zones != nil {
		dst.Zones = make([]Zone, 0, len(src.Zones))
		for _, z := range src.Zones {
			zone := Zone{ID: strings.TrimSpace(z.ID), Name: z.Name, Level: z.Level, CIDRs: z.CIDRs,
				Industrial: z.Industrial, Enforce: !z.Industrial}
			if z.Enforce != nil {
				zone.Enforce = *z.Enforce
			}
			if zone.Name == "" {
				zone.Name = zone.ID
			}
			dst.Zones = append(dst.Zones, zone)
		}
	}
	if src.Conduits != nil {
		dst.Conduits = append([]Conduit(nil), src.Conduits...)
	}
	mergeZoneRule(&dst.NoConduit, src.NoConduit)
	mergeZoneRule(&dst.LevelSkip, src.LevelSkip)
}

func mergeZoneRule(dst *ZoneRule, src *zoneRuleOverlay) {
	if src == nil {
		return
	}
	if src.Enabled != nil {
		dst.Enabled = *src.Enabled
	}
	if src.Severity != nil {
		dst.Severity = *src.Severity
	}
	if src.RealertSeconds != nil {
		dst.RealertSeconds = *src.RealertSeconds
	}
}

// Normalize trims zone ids and fills empty names with the id, the same
// defaults the config file gets. Edits from the API go through it too.
func (c SegmentationConfig) Normalize() SegmentationConfig {
	out := c
	out.Zones = make([]Zone, len(c.Zones))
	for i, z := range c.Zones {
		z.ID = strings.TrimSpace(z.ID)
		z.Name = strings.TrimSpace(z.Name)
		if z.Name == "" {
			z.Name = z.ID
		}
		z.CIDRs = append([]string{}, z.CIDRs...)
		out.Zones[i] = z
	}
	// Empty lists, not null, in JSON.
	out.Conduits = append([]Conduit{}, c.Conduits...)
	return out
}

// Validate checks zones, conduits and the zone alert rules.
func (c SegmentationConfig) Validate() error { return validateSegmentation(c) }

func validateSegmentation(c SegmentationConfig) error {
	ids := map[string]bool{}
	total := 0
	for i, z := range c.Zones {
		if !watchlistIDPattern.MatchString(z.ID) {
			return fmt.Errorf("segmentation.zones[%d]: id %q must be non-empty and use only letters, digits, '_' or '-'", i, z.ID)
		}
		if ids[z.ID] {
			return fmt.Errorf("segmentation.zones: duplicate id %q", z.ID)
		}
		ids[z.ID] = true
		if z.Level < 0 || z.Level > maxZoneLevel {
			return fmt.Errorf("zone %q: level must be between 0 and %d", z.ID, maxZoneLevel)
		}
		if len(z.CIDRs) == 0 {
			return fmt.Errorf("zone %q: cidrs must not be empty", z.ID)
		}
		for _, cidr := range z.CIDRs {
			if _, err := parsePrefix(cidr); err != nil {
				return fmt.Errorf("zone %q: %w", z.ID, err)
			}
		}
		total += len(z.CIDRs)
	}
	if total > maxZonePrefixes {
		return fmt.Errorf("segmentation: %d prefixes exceeds the limit of %d", total, maxZonePrefixes)
	}
	for i, cd := range c.Conduits {
		if !ids[cd.From] || !ids[cd.To] {
			return fmt.Errorf("segmentation.conduits[%d]: from %q and to %q must name zones", i, cd.From, cd.To)
		}
		if cd.From == cd.To {
			return fmt.Errorf("segmentation.conduits[%d]: from and to are the same zone", i)
		}
		for _, p := range cd.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("segmentation.conduits[%d]: port %d out of range", i, p)
			}
		}
	}
	for name, r := range map[string]ZoneRule{"no_conduit": c.NoConduit, "level_skip": c.LevelSkip} {
		if !r.Enabled {
			continue
		}
		if !validSeverity(r.Severity) {
			return fmt.Errorf("segmentation.%s: unknown severity %q (want low|medium|high)", name, r.Severity)
		}
		if r.RealertSeconds < 0 {
			return fmt.Errorf("segmentation.%s: realert_seconds must be >= 0", name)
		}
	}
	return nil
}

// ZoneMatcher maps addresses to zones and checks conduits.
type ZoneMatcher struct {
	zones    []Zone
	prefixes []zonePrefix
	conduits []Conduit
}

type zonePrefix struct {
	prefix netip.Prefix
	zone   int // index into zones
}

// NewZoneMatcher compiles a validated segmentation config. It returns nil
// when no zones are defined.
func NewZoneMatcher(c SegmentationConfig) (*ZoneMatcher, error) {
	if err := validateSegmentation(c); err != nil {
		return nil, err
	}
	if len(c.Zones) == 0 {
		return nil, nil
	}
	m := &ZoneMatcher{zones: c.Zones, conduits: c.Conduits}
	for i, z := range c.Zones {
		for _, cidr := range z.CIDRs {
			p, _ := parsePrefix(cidr) // validated above
			m.prefixes = append(m.prefixes, zonePrefix{prefix: p, zone: i})
		}
	}
	// Longest prefix first, so the first match is the most specific zone.
	slices.SortStableFunc(m.prefixes, func(a, b zonePrefix) int { return b.prefix.Bits() - a.prefix.Bits() })
	return m, nil
}

// Zone returns the most specific zone containing addr, or nil.
func (m *ZoneMatcher) Zone(addr netip.Addr) *Zone {
	if m == nil || !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	for _, zp := range m.prefixes {
		if zp.prefix.Contains(addr) {
			return &m.zones[zp.zone]
		}
	}
	return nil
}

// Zones returns the configured zones.
func (m *ZoneMatcher) Zones() []Zone {
	if m == nil {
		return nil
	}
	return m.zones
}

// Conduits returns the configured conduits.
func (m *ZoneMatcher) Conduits() []Conduit {
	if m == nil {
		return nil
	}
	return m.conduits
}

// Allowed reports whether a packet from zone `from` to zone `to` is covered
// by a conduit. synOnly marks a TCP connection attempt, which is never
// treated as a reply.
func (m *ZoneMatcher) Allowed(from, to string, sport, dport uint16, synOnly bool) bool {
	for _, c := range m.conduits {
		forward := c.From == from && c.To == to
		reverse := c.From == to && c.To == from
		switch {
		case forward && portListed(c.Ports, dport):
			return true
		case reverse && c.Bidirectional && portListed(c.Ports, dport):
			return true
		case reverse && !synOnly && len(c.Ports) > 0 && portListed(c.Ports, sport):
			return true // reply from the service port
		case reverse && !synOnly && len(c.Ports) == 0:
			return true // reply on an any-port conduit
		}
	}
	return false
}

func portListed(ports []int, p uint16) bool {
	return len(ports) == 0 || slices.Contains(ports, int(p))
}

// WatchOnlyPrefixes returns the prefixes of zones where policy drop rules
// need force, keyed by zone id.
func (c SegmentationConfig) WatchOnlyPrefixes() map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	for _, z := range c.Zones {
		if z.Enforce {
			continue
		}
		for _, cidr := range z.CIDRs {
			if p, err := parsePrefix(cidr); err == nil {
				out[z.ID] = append(out[z.ID], p)
			}
		}
	}
	return out
}
