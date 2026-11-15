package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/advisories"
)

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "2026")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	doc := `{"document":{"category":"csaf_security_advisory","title":"T","tracking":{"id":"ICSA-1"}},
	  "product_tree":{"branches":[{"category":"vendor","name":"Acme","branches":[{"category":"product_name","name":"PLC-9","product":{"product_id":"P1"}}]}]},
	  "vulnerabilities":[{"cve":"CVE-1","product_status":{"known_affected":["P1"]}}]}`
	for name, body := range map[string]string{
		"2026/icsa-1.json":     doc,
		"2026/icsa-1.json.asc": "signature",
		"index.json":           `{"not":"an advisory"}`,
		"broken.json":          "{",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	b, skipped, err := build(dir, "test feed", now)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != advisories.BundleFormat || !b.GeneratedAt.Equal(now) || len(b.Advisories) != 1 || b.Advisories[0].ID != "ICSA-1" || skipped != 2 {
		t.Fatalf("bundle = %+v skipped = %d", b, skipped)
	}
	if _, _, err := build(filepath.Join(dir, "missing"), "x", now); err == nil {
		t.Fatal("missing directory accepted")
	}
}
