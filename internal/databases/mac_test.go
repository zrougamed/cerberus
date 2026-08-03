package databases

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseMAC48(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want [6]byte
		ok   bool
	}{
		{"aa:bb:cc:dd:ee:ff", [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, true},
		{"AA-BB-CC-DD-EE-FF", [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, true},
		{"aabbccddeeff", [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, true},
		{"01:00:5e:00:00:fb", [6]byte{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}, true},
		{"bad", [6]byte{}, false},
		{"aa:bb:cc", [6]byte{}, false},
	}
	for _, tc := range cases {
		got, ok := ParseMAC48(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("ParseMAC48(%q) = (%v,%v) want (%v,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestOUIKeyCandidatesOrder(t *testing.T) {
	t.Parallel()
	mac := [6]byte{0x28, 0x6A, 0xBA, 0x1F, 0x2E, 0x03}
	keys := OUIKeyCandidates(mac)
	want := []string{
		"28:6A:BA:1F:20", // MA-S masked
		"28:6A:BA:1F",    // 4 octets
		"28:6A:BA:10",    // MA-M masked
		"28:6A:BA",       // MA-L
	}
	if len(keys) != len(want) {
		t.Fatalf("unexpected keys: %#v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("key[%d]=%q want %q (all %#v)", i, keys[i], want[i], keys)
		}
	}
}

func TestOUIDatabaseLookupSpecialBits(t *testing.T) {
	t.Setenv("CERBERUS_DATA_DIR", filepath.Join(t.TempDir(), "d"))
	db, err := NewOUIDatabase(false)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup("33:33:00:00:00:01"); got != VendorMulticast {
		t.Fatalf("multicast: got %q", got)
	}
	// Random privacy MAC (U/L set, not in fallback) → privacy label.
	if got := db.Lookup("02:00:00:00:00:01"); got != VendorLocalAdmin {
		t.Fatalf("local: got %q", got)
	}
	if got := db.Lookup("B8:27:EB:00:00:01"); got != "Raspberry Pi Foundation" {
		t.Fatalf("fallback OUI: got %q", got)
	}
}

func TestOUIDatabaseLookupLocallyAdministeredKnownVendor(t *testing.T) {
	t.Setenv("CERBERUS_DATA_DIR", filepath.Join(t.TempDir(), "d"))
	db, err := NewOUIDatabase(false)
	if err != nil {
		t.Fatal(err)
	}
	// QEMU 52:54:00 has U/L bit set but should still resolve from the registry.
	if got := db.Lookup("52:54:00:12:34:56"); got != "QEMU/KVM" {
		t.Fatalf("qemu: got %q", got)
	}
	if got := db.Lookup("02:42:AC:11:00:02"); got != "Docker Container" {
		t.Fatalf("docker: got %q", got)
	}
}

func TestOUIIngestMAMAndMAS(t *testing.T) {
	t.Setenv("CERBERUS_DATA_DIR", filepath.Join(t.TempDir(), "d"))
	db := &OUIDatabase{vendors: make(map[string]string), cache: make(map[string]ouiCacheEntry)}
	csv := `Registry,Assignment,Organization Name,Organization Address
MA-L,286ABA,TP-Link Technologies,
MA-M,AABBCC1,Example MA-M Corp,
MA-S,AABBCCDEF,Example MA-S Corp,
`
	n, err := db.ingestIEEEcsv(bytes.NewReader([]byte(csv)))
	if err != nil || n != 3 {
		t.Fatalf("ingest: n=%d err=%v", n, err)
	}
	if got := db.Lookup("28:6A:BA:00:00:01"); got != "TP-Link Technologies" {
		t.Fatalf("MA-L: got %q", got)
	}
	if got := db.Lookup("AA:BB:CC:1A:00:01"); got != "Example MA-M Corp" {
		t.Fatalf("MA-M: got %q", got)
	}
	if got := db.Lookup("AA:BB:CC:DE:F3:01"); got != "Example MA-S Corp" {
		t.Fatalf("MA-S: got %q", got)
	}
}

func TestOUIStaleCachePreferredOverFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CERBERUS_DATA_DIR", dir)
	path := filepath.Join(dir, ouiCacheCSV)
	body := []byte("Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Stale Vendor Corp,\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	db, err := NewOUIDatabase(false)
	if err != nil {
		t.Fatal(err)
	}
	if !db.stale {
		t.Fatal("expected stale flag")
	}
	if got := db.Lookup("AA:BB:CC:00:00:01"); got != "Stale Vendor Corp" {
		t.Fatalf("stale cache should still resolve: got %q", got)
	}
}
