// Package advisories matches assets against an offline bundle of published
// security advisories, so sites without internet access can still see
// which of their controllers have known vulnerabilities.
package advisories

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// BundleFormat is the version of the bundle file layout.
const BundleFormat = 1

// Bundle is the file tools/advisorygen writes.
type Bundle struct {
	Format      int        `json:"format"`
	GeneratedAt time.Time  `json:"generated_at"`
	Source      string     `json:"source"`
	Advisories  []Advisory `json:"advisories"`
}

// Advisory is one published advisory and the products it affects.
type Advisory struct {
	ID        string    `json:"id"` // e.g. ICSA-26-020-02
	Title     string    `json:"title"`
	URL       string    `json:"url,omitempty"`
	Published time.Time `json:"published"`
	Severity  string    `json:"severity"` // low, medium, high, critical
	Score     float64   `json:"score"`    // highest CVSS base score
	CVEs      []string  `json:"cves"`
	Products  []Product `json:"products"`
}

// Product is one affected vendor/product/version entry.
type Product struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"` // range expression; empty = all versions
}

// Confidence says how sure a match is.
const (
	// MatchVersion: vendor and product match and the firmware falls in
	// the affected range (or every version is affected).
	MatchVersion = "affected version"
	// MatchProduct: vendor and product match but the firmware is unknown
	// or cannot be compared with the advisory's range.
	MatchProduct = "product only"
)

// Match is an advisory that applies to an asset.
type Match struct {
	Advisory
	Product    string `json:"product"`  // the advisory product that matched
	Affected   string `json:"affected"` // its version expression
	Confidence string `json:"confidence"`
}

// Asset is what the matcher needs to know about a device.
type Asset struct {
	Vendor   string // reported vendor, else the OUI vendor
	Model    string
	Firmware string
}

// maxBundleBytes bounds the file read: the full CISA OT feed is a few MB.
const maxBundleBytes = 256 << 20

// Load reads and indexes a bundle file.
func Load(path string) (*Index, error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open advisory bundle: %w", err)
	}
	defer root.Close()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("open advisory bundle: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read advisory bundle: %w", err)
	}
	if info.Size() > maxBundleBytes {
		return nil, fmt.Errorf("advisory bundle is %d bytes, more than the %d limit", info.Size(), maxBundleBytes)
	}
	var b Bundle
	if err := json.NewDecoder(f).Decode(&b); err != nil {
		return nil, fmt.Errorf("parse advisory bundle: %w", err)
	}
	if b.Format != BundleFormat {
		return nil, fmt.Errorf("advisory bundle format %d, want %d (regenerate it with tools/advisorygen)", b.Format, BundleFormat)
	}
	return NewIndex(b), nil
}

// Index is a bundle prepared for matching. It caches results per
// (vendor, model, firmware): the console asks for the same assets every few
// seconds and a full scan of the CISA feed costs about 0.35 ms per asset.
type Index struct {
	bundle  Bundle
	entries []entry

	mu    sync.Mutex
	cache map[Asset][]Match
}

// maxCachedAssets bounds the match cache; past it the cache starts over.
const maxCachedAssets = 4096

type entry struct {
	adv     int // index into bundle.Advisories
	product Product
	vendor  string // normalised
	name    string // compacted
	ranges  versionSet
}

// NewIndex normalises every product once so matching stays cheap.
func NewIndex(b Bundle) *Index {
	idx := &Index{bundle: b}
	for i, a := range b.Advisories {
		for _, p := range a.Products {
			name := compact(p.Name)
			if len(name) < minProductLen {
				continue
			}
			idx.entries = append(idx.entries, entry{adv: i, product: p, vendor: normVendor(p.Vendor), name: name, ranges: parseVersionSet(p.Version)})
		}
	}
	return idx
}

// Info summarises the loaded bundle.
type Info struct {
	GeneratedAt time.Time `json:"generated_at"`
	Source      string    `json:"source"`
	Advisories  int       `json:"advisories"`
}

// Info describes the bundle.
func (x *Index) Info() Info {
	return Info{GeneratedAt: x.bundle.GeneratedAt, Source: x.bundle.Source, Advisories: len(x.bundle.Advisories)}
}

// Match returns the advisories that apply to an asset, highest score
// first, one entry per advisory. The result must not be modified.
func (x *Index) Match(a Asset) []Match {
	x.mu.Lock()
	if m, ok := x.cache[a]; ok {
		x.mu.Unlock()
		return m
	}
	x.mu.Unlock()
	m := x.match(a)
	x.mu.Lock()
	if x.cache == nil || len(x.cache) >= maxCachedAssets {
		x.cache = make(map[Asset][]Match)
	}
	x.cache[a] = m
	x.mu.Unlock()
	return m
}

func (x *Index) match(a Asset) []Match {
	vendor, model := normVendor(a.Vendor), compact(a.Model)
	if vendor == "" || len(model) < minProductLen {
		return nil
	}
	fw, fwOK := parseVersion(a.Firmware)
	best := map[int]Match{}
	for _, e := range x.entries {
		if !vendorMatches(vendor, e.vendor) || !productMatches(model, e.name) {
			continue
		}
		conf := MatchProduct
		switch {
		case e.ranges.all:
			conf = MatchVersion
		case fwOK && e.ranges.ok:
			if !e.ranges.contains(fw) {
				continue // a known firmware outside the affected range
			}
			conf = MatchVersion
		}
		if prev, seen := best[e.adv]; seen && (prev.Confidence == MatchVersion || conf == MatchProduct) {
			continue
		}
		best[e.adv] = Match{Advisory: x.bundle.Advisories[e.adv], Product: e.product.Name, Affected: e.product.Version, Confidence: conf}
	}
	out := make([]Match, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// minProductLen keeps one- and two-character names from matching
// everything.
const minProductLen = 3

// compact lower-cases and keeps only letters and digits, so "S7-1500" and
// "SIMATIC S7-1500 CPU" can be compared.
func compact(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Company suffixes that vary between sources ("Siemens AG", "Siemens").
var vendorSuffixes = map[string]bool{
	"ag": true, "gmbh": true, "inc": true, "incorporated": true, "corp": true, "corporation": true,
	"co": true, "company": true, "ltd": true, "limited": true, "llc": true, "plc": true, "sa": true,
	"se": true, "srl": true, "spa": true, "bv": true, "nv": true, "kg": true, "ab": true, "oy": true,
}

func normVendor(s string) string {
	var words []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if !vendorSuffixes[w] {
			words = append(words, w)
		}
	}
	return strings.Join(words, "")
}

func vendorMatches(asset, adv string) bool {
	if asset == "" || adv == "" {
		return false
	}
	return asset == adv || strings.HasPrefix(asset, adv) || strings.HasPrefix(adv, asset)
}

// productMatches compares compacted names: either may contain the other
// (the device reports "ET 200SP", the advisory lists "SIMATIC ET 200SP").
func productMatches(model, product string) bool {
	return strings.Contains(product, model) || strings.Contains(model, product)
}
