package databases

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadLimited(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		limit   int64
		wantErr bool
	}{
		{name: "empty", body: "", limit: 4},
		{name: "under limit", body: "abc", limit: 4},
		{name: "exactly at limit", body: "abcd", limit: 4},
		{name: "one byte over", body: "abcde", limit: 4, wantErr: true},
		{name: "far over", body: strings.Repeat("x", 1<<16), limit: 1024, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := readLimited(strings.NewReader(tc.body), tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %d-byte body with limit %d", len(tc.body), tc.limit)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.body {
				t.Fatalf("got %q, want %q", got, tc.body)
			}
		})
	}
}

func TestHTTPGetBody_RejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stream one byte more than the cap without buffering it all here.
		chunk := make([]byte, 1<<20)
		remaining := maxRegistryBody + 1
		for remaining > 0 {
			n := min(remaining, len(chunk))
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	t.Cleanup(srv.Close)

	db := &OUIDatabase{}
	_, err := db.httpGetBody(&http.Client{Timeout: 10 * time.Second}, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestHTTPGetBody_ReturnsBodyAndRejectsNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("Registry,Assignment\n"))
	}))
	t.Cleanup(srv.Close)

	db := &OUIDatabase{}
	client := &http.Client{Timeout: 5 * time.Second}

	body, err := db.httpGetBody(client, srv.URL+"/oui.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "Registry,Assignment\n" {
		t.Fatalf("unexpected body %q", body)
	}

	if _, err := db.httpGetBody(client, srv.URL+"/missing"); err == nil {
		t.Fatal("expected error for 404 response")
	}
}
