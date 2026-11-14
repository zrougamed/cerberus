package databases

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedSnapshot_ResolvesEveryRegistry(t *testing.T) {
	t.Setenv("CERBERUS_DATA_DIR", filepath.Join(t.TempDir(), "d"))
	db, err := NewOUIDatabase(false)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(db.vendors); n < 50000 {
		t.Fatalf("embedded snapshot too small: %d entries", n)
	}
	if db.snapshot.IsZero() {
		t.Fatal("snapshot date not parsed from the embedded header")
	}
	cases := []struct{ mac, want string }{
		{"9c:69:d3:20:df:d7", "ASIX Electronics Corporation"},  // MA-L
		{"b4:8c:9d:b5:aa:bd", "AzureWave Technology Inc."},     // MA-L
		{"C8:5C:E2:70:00:01", "SYNERGY SYSTEMS AND SOLUTIONS"}, // MA-M C85CE27
		{"40:D8:55:0D:70:01", "Avant Technologies"},            // IAB 40D8550D7
		{"52:54:00:12:34:56", "QEMU/KVM"},                      // well-known local
		{"02:42:AC:11:00:02", "Docker Container"},              // well-known local
		{"06:00:00:00:00:01", VendorLocalAdmin},                // random privacy MAC
		{"01:00:5E:00:00:FB", VendorMulticast},
	}
	for _, tc := range cases {
		if got := db.Lookup(tc.mac); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.mac, got, tc.want)
		}
	}
	// MA-S: the registry's parent MA-L block belongs to the IEEE RA; the
	// 36-bit assignment must win over it.
	if got := db.Lookup("8C:1F:64:AF:A0:01"); strings.Contains(got, "IEEE Registration Authority") || got == VendorUnknown {
		t.Errorf("MA-S 8C1F64AFA resolved to %q", got)
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func TestParseEmbeddedOUI(t *testing.T) {
	t.Parallel()
	m, snap, err := parseEmbeddedOUI(gz(t, "# snapshot 2026-01-02 entries 2\nAA:BB:CC\tAcme\nbroken line\n\tno key\nAA:BB:CC:D0\tAcme M\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["AA:BB:CC:D0"] != "Acme M" || snap.Format("2006-01-02") != "2026-01-02" {
		t.Fatalf("got %v %v", m, snap)
	}
	if _, _, err := parseEmbeddedOUI([]byte("not gzip")); err == nil {
		t.Fatal("expected error for non-gzip data")
	}
}

func TestHTTPGetBody_SendsIdentifyingUserAgent(t *testing.T) {
	t.Parallel()
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	if _, err := (&OUIDatabase{}).httpGetBody(srv.Client(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ua, "Cerberus-Network-Monitor/") || !strings.Contains(ua, "github.com/zrougamed/cerberus") {
		t.Fatalf("user agent %q", ua)
	}
}

func TestHTTPGetBody_RefusalExplainsFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	_, err := (&OUIDatabase{}).httpGetBody(srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "418") || !strings.Contains(err.Error(), "embedded snapshot") {
		t.Fatalf("got %v", err)
	}
}
