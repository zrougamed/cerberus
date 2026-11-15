package advisories

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"V32.011":           "32.11",
		"MS_4.1_14142":      "4.1.14142",
		"6.3_HF3":           "6.3.3",
		"v3.20":             "3.20",
		"2.0_HotFix_2":      "2.0.2",
		"1.2.3.4.5.6.7.8.9": "1.2.3.4.5.6.7.8",
	} {
		v, ok := parseVersion(in)
		if !ok || v.String() != want {
			t.Errorf("parseVersion(%q) = %v %v, want %s", in, v, ok, want)
		}
	}
	for _, bad := range []string{"", "beta", "1234567890123"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("parseVersion(%q) accepted", bad)
		}
	}
}

func TestVersionSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		expr    string
		version string
		ok, hit bool
	}{
		{"<5.2.11.18", "5.2.11.17", true, true},
		{"<5.2.11.18", "5.2.11.18", true, false},
		{"vers:Asset_Suite/<=9.7", "9.7", true, true},
		{"vers:Asset_Suite/<=9.7", "9.7.1", true, false},
		{"vers:generic/>=2.0|<3.1", "2.5", true, true},
		{"vers:generic/>=2.0|<3.1", "3.1", true, false},
		{"vers:generic/>2.0|!=2.4", "2.4", true, false},
		{"V1.001", "1.1", true, true},
		{"=1.1", "1.2", true, false},
		{"<MS_4.1_14142", "MS_4.1_14000", true, true},
		{">=1.0", "0.9", true, false},
	}
	for _, tt := range tests {
		s := parseVersionSet(tt.expr)
		v, _ := parseVersion(tt.version)
		if s.ok != tt.ok || (s.ok && s.contains(v) != tt.hit) {
			t.Errorf("%q contains %q: ok=%v hit=%v, want ok=%v hit=%v", tt.expr, tt.version, s.ok, s.contains(v), tt.ok, tt.hit)
		}
	}
	for _, all := range []string{"", "*", "vers:all/*"} {
		if s := parseVersionSet(all); !s.all || !s.ok {
			t.Errorf("%q should mean all versions", all)
		}
	}
	for _, bad := range []string{"vers:noslash", "<beta", "latest"} {
		if s := parseVersionSet(bad); s.ok || s.all {
			t.Errorf("%q should be unparsable", bad)
		}
	}
}

func testBundle() Bundle {
	return Bundle{Format: BundleFormat, GeneratedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Source: "test", Advisories: []Advisory{
		{ID: "ICSA-A", Title: "Modicon controllers", Score: 8.8, Severity: "high", CVEs: []string{"CVE-1"}, Products: []Product{
			{Vendor: "Schneider Electric", Name: "Modicon Controller M241", Version: "<5.2.11.18"},
			{Vendor: "Schneider Electric", Name: "Modicon Controller M258", Version: "vers:all/*"},
		}},
		{ID: "ICSA-B", Title: "SIMATIC", Score: 9.8, Severity: "critical", Products: []Product{
			{Vendor: "Siemens", Name: "SIMATIC S7-1500 CPU family", Version: "<3.1"},
			{Vendor: "Siemens", Name: "SIMATIC S7-1500 CPU family", Version: "vers:all/*"},
		}},
		{ID: "ICSA-C", Title: "Odd versions", Score: 5, Severity: "medium", Products: []Product{
			{Vendor: "Siemens AG", Name: "ET 200SP", Version: "<build-latest"},
			{Vendor: "Siemens", Name: "X1", Version: "*"}, // too short to index
		}},
	}}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	idx := NewIndex(testBundle())
	tests := []struct {
		name  string
		asset Asset
		want  map[string]string // advisory id -> confidence
	}{
		{"affected firmware", Asset{"Schneider Electric", "M241", "5.2.10.0"}, map[string]string{"ICSA-A": MatchVersion}},
		{"fixed firmware", Asset{"Schneider Electric", "M241", "5.2.11.18"}, map[string]string{}},
		{"unknown firmware", Asset{"Schneider Electric", "M241", ""}, map[string]string{"ICSA-A": MatchProduct}},
		{"all versions", Asset{"Schneider Electric", "M258", "9.9"}, map[string]string{"ICSA-A": MatchVersion}},
		{"vendor suffix and product inside a longer name", Asset{"Siemens AG", "S7-1500", "4.0"}, map[string]string{"ICSA-B": MatchVersion}},
		{"unparsable range", Asset{"Siemens", "ET 200SP", "4.2"}, map[string]string{"ICSA-C": MatchProduct}},
		{"other vendor", Asset{"Rockwell Automation", "M241", "1.0"}, map[string]string{}},
		{"no vendor", Asset{"", "M241", "1.0"}, map[string]string{}},
		{"model too short", Asset{"Siemens", "X1", ""}, map[string]string{}},
	}
	for _, tt := range tests {
		got := idx.Match(tt.asset)
		if len(got) != len(tt.want) {
			t.Errorf("%s: %d matches %+v, want %v", tt.name, len(got), got, tt.want)
			continue
		}
		for _, m := range got {
			if tt.want[m.ID] != m.Confidence {
				t.Errorf("%s: %s confidence %q, want %q", tt.name, m.ID, m.Confidence, tt.want[m.ID])
			}
		}
	}
	// Highest score first.
	two := NewIndex(Bundle{Advisories: []Advisory{
		{ID: "LOW", Score: 3, Products: []Product{{Vendor: "Acme", Name: "PLC-9"}}},
		{ID: "HIGH", Score: 9, Products: []Product{{Vendor: "Acme", Name: "PLC-9"}}},
		{ID: "ALSO-9", Score: 9, Products: []Product{{Vendor: "Acme", Name: "PLC-9"}}},
	}})
	got := two.Match(Asset{"Acme Inc", "plc-9", ""})
	if len(got) != 3 || got[0].ID != "ALSO-9" || got[1].ID != "HIGH" || got[2].ID != "LOW" {
		t.Fatalf("order = %+v", got)
	}
	if info := idx.Info(); info.Advisories != 3 || info.Source != "test" {
		t.Fatalf("info = %+v", info)
	}
}

func writeBundle(t *testing.T, v any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "advisories.json")
	data, _ := json.Marshal(v)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	t.Parallel()
	idx, err := Load(writeBundle(t, testBundle()))
	if err != nil || idx.Info().Advisories != 3 {
		t.Fatalf("load: %v %+v", err, idx)
	}
	old := testBundle()
	old.Format = 0
	if _, err := Load(writeBundle(t, old)); err == nil || !strings.Contains(err.Error(), "regenerate") {
		t.Fatalf("old format: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("corrupt bundle loaded")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing bundle loaded")
	}
	if _, err := Load("/nonexistent-dir/advisories.json"); err == nil {
		t.Fatal("missing dir loaded")
	}
}

const csafFixture = `{
  "document": {
    "category": "csaf_security_advisory",
    "title": "Example Automation Controllers",
    "tracking": {"id": "ICSA-99-001-01", "initial_release_date": "2026-03-01T07:00:00Z", "current_release_date": "2026-03-02T07:00:00Z"},
    "references": [
      {"category": "self", "url": "https://example.com/csaf/icsa-99-001-01.json"},
      {"category": "external", "url": "https://vendor.example/psirt.pdf"},
      {"category": "self", "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-99-001-01"}
    ]
  },
  "product_tree": {"branches": [{"category": "vendor", "name": "Example Automation", "branches": [
    {"category": "product_family", "name": "XC Series", "branches": [
      {"category": "product_name", "name": "XC-200 Controller", "branches": [
        {"category": "product_version_range", "name": "vers:generic/<4.2", "product": {"product_id": "P1", "name": "XC-200 <4.2"}},
        {"category": "product_version", "name": "4.2", "product": {"product_id": "P2", "name": "XC-200 4.2"}}
      ]}
    ]},
    {"category": "product_name", "name": "XC Gateway", "product": {"product_id": "P3", "name": "XC Gateway"}}
  ]}]},
  "vulnerabilities": [
    {"cve": "CVE-2026-0002", "scores": [{"cvss_v3": {"baseScore": 7.5}}], "product_status": {"known_affected": ["P1", "P3"], "fixed": ["P2"]}},
    {"cve": "CVE-2026-0001", "scores": [{"cvss_v4": {"baseScore": 9.3}}], "product_status": {"known_affected": ["P1"]}}
  ]
}`

func TestParseCSAF(t *testing.T) {
	t.Parallel()
	a, ok, err := ParseCSAF([]byte(csafFixture))
	if err != nil || !ok {
		t.Fatalf("parse: %v ok=%v", err, ok)
	}
	if a.ID != "ICSA-99-001-01" || a.Severity != "critical" || a.Score != 9.3 || len(a.CVEs) != 2 || a.CVEs[0] != "CVE-2026-0001" {
		t.Fatalf("advisory = %+v", a)
	}
	if a.URL != "https://www.cisa.gov/news-events/ics-advisories/icsa-99-001-01" || !a.Published.Equal(time.Date(2026, 3, 1, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("url/published = %q %v", a.URL, a.Published)
	}
	want := []Product{
		{Vendor: "Example Automation", Name: "XC Gateway"},
		{Vendor: "Example Automation", Name: "XC-200 Controller", Version: "vers:generic/<4.2"},
	}
	if len(a.Products) != 2 || a.Products[0] != want[0] || a.Products[1] != want[1] {
		t.Fatalf("products = %+v", a.Products)
	}
	// The fixed version (P2) is not listed, and matching uses the range.
	idx := NewIndex(Bundle{Advisories: []Advisory{a}})
	if got := idx.Match(Asset{"Example Automation", "XC-200", "4.1"}); len(got) != 1 || got[0].Confidence != MatchVersion {
		t.Fatalf("match 4.1 = %+v", got)
	}
	if got := idx.Match(Asset{"Example Automation", "XC-200", "4.2"}); len(got) != 0 {
		t.Fatalf("fixed 4.2 matched: %+v", got)
	}
}

func TestParseCSAF_Skips(t *testing.T) {
	t.Parallel()
	if _, _, err := ParseCSAF([]byte("not json")); err == nil {
		t.Fatal("garbage parsed")
	}
	notAdvisory := strings.Replace(csafFixture, "csaf_security_advisory", "csaf_informational_advisory", 1)
	if _, ok, _ := ParseCSAF([]byte(notAdvisory)); ok {
		t.Fatal("informational document accepted")
	}
	noAffected := strings.ReplaceAll(csafFixture, `"known_affected": ["P1", "P3"]`, `"known_affected": []`)
	noAffected = strings.ReplaceAll(noAffected, `"known_affected": ["P1"]`, `"known_affected": ["P9"]`)
	if _, ok, _ := ParseCSAF([]byte(noAffected)); ok {
		t.Fatal("advisory without affected products accepted")
	}
	for score, want := range map[float64]string{9: "critical", 7: "high", 4: "medium", 0.1: "low", 0: "unknown"} {
		if got := severityFor(score); got != want {
			t.Errorf("severityFor(%v) = %s, want %s", score, got, want)
		}
	}
}

func FuzzParseVersionSet(f *testing.F) {
	f.Add("vers:generic/>=2.0|<3.1", "2.5")
	f.Add("<MS_4.1_14142", "MS_4.1_1")
	f.Fuzz(func(t *testing.T, expr, ver string) {
		s := parseVersionSet(expr)
		if v, ok := parseVersion(ver); ok && s.ok {
			_ = s.contains(v)
		}
	})
}

func TestParseCSAF_SelfURLFallback(t *testing.T) {
	t.Parallel()
	doc := strings.Replace(csafFixture, "https://www.cisa.gov/news-events/ics-advisories/icsa-99-001-01", "https://psirt.example/advisory/1", 1)
	a, _, _ := ParseCSAF([]byte(doc))
	if a.URL != "https://psirt.example/advisory/1" {
		t.Fatalf("url = %q", a.URL)
	}
}

func TestLoad_SizeLimit(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: no disk space is used.
	if err := f.Truncate(maxBundleBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestMatch_CachedAndBounded(t *testing.T) {
	t.Parallel()
	idx := NewIndex(testBundle())
	a := Asset{"Schneider Electric", "M241", "5.2.10.0"}
	first := idx.Match(a)
	if second := idx.Match(a); len(second) != 1 || &second[0] != &first[0] {
		t.Fatal("second lookup not served from the cache")
	}
	for i := range maxCachedAssets + 1 {
		idx.Match(Asset{"Schneider Electric", "M241", strconv.Itoa(i)})
	}
	idx.mu.Lock()
	n := len(idx.cache)
	idx.mu.Unlock()
	if n > maxCachedAssets {
		t.Fatalf("cache grew to %d", n)
	}
}

func BenchmarkMatchCached(b *testing.B) {
	idx := NewIndex(testBundle())
	a := Asset{"Schneider Electric", "M241", "5.2.10.0"}
	b.ReportAllocs()
	for range b.N {
		idx.Match(a)
	}
}
