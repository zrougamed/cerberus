package tui

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

var testNow = time.Date(2026, 11, 15, 10, 0, 30, 0, time.UTC)

// fakeAPI serves the testdata fixtures like a running Cerberus and records
// the changes it receives.
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	posts    map[string]string // path -> body
	token    string            // required bearer token, if set
	missing  map[string]bool   // endpoints answering 404
	failing  map[string]bool   // endpoints answering 500
	srv      *httptest.Server
	requests []string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, posts: map[string]string{}, missing: map[string]bool{}, failing: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"missing or invalid bearer token"}`))
		return
	}
	if f.missing[name] {
		http.NotFound(w, r)
		return
	}
	if f.failing[name] {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.posts[r.URL.Path] = string(b)
		f.mu.Unlock()
		if strings.HasPrefix(name, "baseline/forget") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"your role (viewer) cannot do this; it needs analyst"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
		return
	}
	if strings.HasPrefix(name, "assets/") && strings.HasSuffix(name, "/advisories") {
		name = "asset_advisories"
	}
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(f.srv.URL, f.token, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testModel returns a model that has fetched every view once.
func testModel(t *testing.T, f *fakeAPI, w, h int) model {
	t.Helper()
	m := newModel(f.client(t), 2*time.Second)
	m.now = func() time.Time { return testNow }
	m.width, m.height = w, h
	m.fetchedAt = testNow // not the first fetch, so no real tick timer starts
	for v := view(0); v < viewCount; v++ {
		m.view = v
		m = run(t, m, m.fetchCmd())
	}
	m.view = viewOverview
	return m
}

// run executes cmd and feeds its message (and any batch) back into m.
func run(t *testing.T, m model, cmd tea.Cmd) model {
	t.Helper()
	if cmd == nil {
		return m
	}
	msg := cmd()
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			if c != nil {
				if _, isTick := c().(tickMsg); !isTick {
					m = run(t, m, c)
				}
			}
		}
		return m
	}
	nm, next := m.Update(msg)
	m = nm.(model)
	if _, isTick := msg.(tickMsg); isTick {
		return m
	}
	if next != nil {
		if _, isTick := next().(tickMsg); isTick {
			return m
		}
		return run(t, m, next)
	}
	return m
}

func press(t *testing.T, m model, keys ...string) model {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "up":
			msg = tea.KeyPressMsg{Code: tea.KeyUp}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "pgdown":
			msg = tea.KeyPressMsg{Code: tea.KeyPgDown}
		case "pgup":
			msg = tea.KeyPressMsg{Code: tea.KeyPgUp}
		case "space":
			msg = tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
		case "ctrl+c":
			msg = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		nm, cmd := m.Update(msg)
		m = nm.(model)
		m = run(t, m, cmd)
	}
	return m
}

func typeText(t *testing.T, m model, s string) model {
	t.Helper()
	for _, r := range s {
		m = press(t, m, string(r))
	}
	return m
}

// screen renders m and checks every line fits the terminal.
func screen(t *testing.T, m model) string {
	t.Helper()
	out := m.render()
	lines := strings.Split(out, "\n")
	if len(lines) != max(4, m.height) {
		t.Fatalf("%s: %d lines, want %d", viewNames[m.view], len(lines), m.height)
	}
	for i, l := range lines {
		if w := ansi.StringWidth(l); w > max(20, m.width) {
			t.Fatalf("%s line %d is %d wide (> %d): %q", viewNames[m.view], i, w, m.width, ansi.Strip(l))
		}
	}
	return ansi.Strip(out)
}

func mustContain(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
}

func TestEveryViewFits(t *testing.T) {
	f := newFakeAPI(t)
	for _, size := range [][2]int{{80, 24}, {120, 40}, {200, 60}, {30, 5}} {
		m := testModel(t, f, size[0], size[1])
		// Add samples so the charts draw.
		for i := range 30 {
			m.pktRate.add(float64(i % 7 * 10))
			m.score.add(float64(i%5) / 2)
			m.protoRate["tcp"].add(float64(i))
		}
		for v := view(0); v < viewCount; v++ {
			m.view = v
			screen(t, m)
		}
		m.view = viewDevices
		m = press(t, m, "enter")
		screen(t, m)
		m.view, m.detail = viewAlerts, false
		m = press(t, m, "enter")
		screen(t, m)
		m.help = true
		screen(t, m)
	}
}

func TestViewContent(t *testing.T) {
	f := newFakeAPI(t)
	m := testModel(t, f, 160, 50)
	m.record(m.snap, testNow.Add(2*time.Second))
	for i := range 20 {
		m.pktRate.add(float64(i * 3))
	}
	mustContain(t, screen(t, m), "Cerberus", "abc1234", "alice (analyst)", "Traffic", "Devices     8",
		"Policy      enforcing, kernel attached, 3 rules, 2 filters", "Baseline    learning, 2 new flows",
		"Captures    on, buffer 5.0 MB", "4 kernel drops", "3964 from cisagov/CSAF, 120 days old (stale)", "Top services", "Latest alerts", "ANOMALY")

	m = press(t, m, "2")
	mustContain(t, screen(t, m), "8 devices, sorted by last seen", "10.20.0.50", "Rockwell Automation")
	m = press(t, m, "s")
	mustContain(t, screen(t, m), "sorted by IP")
	m = press(t, m, "s", "s", "s")
	mustContain(t, screen(t, m), "sorted by last seen")

	// Filter, then open the device.
	m = press(t, m, "/")
	m = typeText(t, m, "10.20.0.5")
	m = press(t, m, "enter")
	s := screen(t, m)
	mustContain(t, s, "1 devices", "filter: 10.20.0.5")
	m = press(t, m, "enter")
	mustContain(t, screen(t, m), "Reports itself as Schneider Electric M580, firmware v3.20", "zone Line 1", "MODBUS",
		"40 requests, 41 responses, 1 exceptions", "peers: 10.20.0.10", "ICSA-25-001-01", "< v3.40 (affected version)",
		"Role Controller", "DNS queries", "TLS server names", "HTTP hosts")
	m = press(t, m, "esc")
	if m.detail {
		t.Fatal("esc should close the detail")
	}
	m = press(t, m, "esc")
	if m.filter[viewDevices] != "" {
		t.Fatal("esc should clear the filter")
	}

	m = press(t, m, "3")
	mustContain(t, screen(t, m), "rule alerts, newest first", "s7_program", "T0843", "✓ alice")
	m = press(t, m, "4")
	mustContain(t, screen(t, m), "ANOMALY", "Packet rate is four times higher", "Packet rate", "Recent anomalies")
	m = press(t, m, "5")
	mustContain(t, screen(t, m), "3 industrial assets", "Schneider Electric", "M580", "2 high", "HMI*", "Eng. workstation")
	m = press(t, m, "s", "s")
	mustContain(t, screen(t, m), "sorted by advisories")
	m = press(t, m, "6")
	mustContain(t, screen(t, m), "L1 Basic control", "Line 1", "Office", "Office → Line 1  ports 502", "Line 1 ↔ Office  any port",
		"refused", "Traffic with no conduit")
	m = press(t, m, "7")
	mustContain(t, screen(t, m), "2 new", "1 flows not recorded", "10.0.4.7")
	m = press(t, m, "8")
	mustContain(t, screen(t, m), "enforcing", "MAC 3c:22:fb:10:aa:09", "sni *.evil.example", "10.9.0.0/16", "tcp dst 23", "alice@10.0.0.2")
	m = press(t, m, "9")
	mustContain(t, screen(t, m), "Buffer 5.0 MB, 900 frames on eth0", "4 frames dropped", "no, 2 dropped")
	m = press(t, m, "0")
	mustContain(t, screen(t, m), "DNS query types", "NOERROR", "updates.vendor.example", "TLS 1.3", "historian.plant.example", "doh")
	m = press(t, m, "tab")
	if m.view != viewOverview {
		t.Fatalf("tab from the last view = %v", m.view)
	}
	m = press(t, m, "shift+tab")
	if m.view != viewDNS {
		t.Fatalf("shift+tab = %v", m.view)
	}
}

func TestAlertAckAndDetail(t *testing.T) {
	f := newFakeAPI(t)
	m := testModel(t, f, 120, 40)
	m = press(t, m, "3", "enter")
	s := screen(t, m)
	mustContain(t, s, "Device ", "ATT&CK for ICS")
	// The detail stays on the same alert when the list changes.
	id := m.alertID
	m.snap.Alerts = append(m.snap.Alerts[:0:0], m.snap.Alerts...)
	if a, _ := m.selectedAlert(); a.ID != id {
		t.Fatal("detail lost its alert")
	}
	m = press(t, m, "esc", "a")
	if m.prompt.kind != promptAck {
		t.Fatal("a should open the note prompt")
	}
	m = typeText(t, m, "checked x")
	m = press(t, m, "backspace")
	if !strings.Contains(screen(t, m), "checked") {
		t.Fatal("prompt not shown")
	}
	m = press(t, m, "enter")
	if m.status != "Alert acknowledged." {
		t.Fatalf("status = %q", m.status)
	}
	var found bool
	for p, body := range f.posts {
		if strings.HasSuffix(p, "/ack") && strings.Contains(body, `"note":"checked"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("ack not posted: %v", f.posts)
	}

	// Without the analyst role the console says why.
	m.snap.Session = session{Role: "viewer", Authenticated: true, WritesEnabled: true}
	m = press(t, m, "a")
	mustContain(t, m.status, "needs the analyst role", "Your role is viewer")
	m.snap.Session = session{Role: "none", WritesEnabled: true}
	m = press(t, m, "a")
	mustContain(t, m.status, "CERBERUS_API_TOKEN")
	m.snap.Session = session{Role: "none"}
	m = press(t, m, "a")
	mustContain(t, m.status, "turned off")
}

func TestBaselineActions(t *testing.T) {
	f := newFakeAPI(t)
	m := testModel(t, f, 120, 40)
	m = press(t, m, "7", "A")
	mustContain(t, m.status, "Mark flows with Space first")
	m = press(t, m, "space", "space")
	if len(m.marked) != 2 {
		t.Fatalf("marked = %v", m.marked)
	}
	mustContain(t, screen(t, m), "✓ new")
	m = press(t, m, "A")
	if m.prompt.kind != promptConfirm {
		t.Fatal("A should ask to confirm")
	}
	m = press(t, m, "n")
	if m.prompt.kind != promptNone || len(m.marked) != 2 {
		t.Fatal("n should cancel and keep the marks")
	}
	m = press(t, m, "A", "y")
	if body := f.posts["/api/v1/baseline/approve"]; !strings.Contains(body, "new0000000000001") || !strings.Contains(body, "new0000000000002") {
		t.Fatalf("approve body = %q", body)
	}
	mustContain(t, m.status, "2 flow(s): approve done")
	m = press(t, m, "space", "F", "enter")
	mustContain(t, m.status, "Failed: your role (viewer) cannot do this")
	m.snap.Session.Role = "viewer"
	m = press(t, m, "A")
	mustContain(t, m.status, "needs the analyst role")
}

func TestKeysAndModes(t *testing.T) {
	f := newFakeAPI(t)
	m := testModel(t, f, 100, 30)
	m = press(t, m, "?")
	if !m.help {
		t.Fatal("? should show help")
	}
	mustContain(t, screen(t, m), "Keys", "acknowledge")
	m = press(t, m, "x")
	if m.help {
		t.Fatal("any key closes help")
	}
	m = press(t, m, "p")
	if !m.paused || !strings.Contains(screen(t, m), "paused") {
		t.Fatal("p should pause")
	}
	// A tick while paused does not fetch.
	nm, cmd := m.Update(tickMsg(testNow))
	if nm.(model).inflight || cmd == nil {
		t.Fatal("paused tick should only re-arm")
	}
	m = press(t, m, "p", "2", "down", "down", "up", "pgdown", "pgup", "G")
	if m.sel[viewDevices] != 7 {
		t.Fatalf("G = %d", m.sel[viewDevices])
	}
	m = press(t, m, "g", "j", "k", "l", "h", "right", "left", "home", "end")
	m = press(t, m, "/", "z", "esc")
	if m.filter[viewDevices] != "" || m.prompt.kind != promptNone {
		t.Fatal("esc in the filter prompt clears it")
	}
	m = press(t, m, "1", "/", "s", "enter", "a", "A", "space")
	if m.prompt.kind != promptNone || m.sortCol[viewOverview] != 0 {
		t.Fatal("list keys do nothing on the overview")
	}
	m = press(t, m, "r")
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil || cmd() != tea.Quit() {
		t.Fatal("q should quit")
	}
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil || cmd() != tea.Quit() {
		t.Fatal("ctrl+c should quit")
	}
	nm, _ = m.Update(tea.WindowSizeMsg{Width: 90, Height: 33})
	if nm.(model).width != 90 || nm.(model).height != 33 {
		t.Fatal("window size not applied")
	}
	v := m.View()
	if !v.AltScreen || !strings.Contains(v.WindowTitle, "127.0.0.1") {
		t.Fatalf("view = %+v", v)
	}
	if m.Init() == nil {
		t.Fatal("Init should fetch")
	}
	// Ticks fetch when idle and are skipped while a fetch runs.
	m.inflight = false
	nm, _ = m.Update(tickMsg(testNow))
	if !nm.(model).inflight {
		t.Fatal("tick should fetch")
	}
	nm, _ = nm.(model).Update(tickMsg(testNow))
	if !nm.(model).inflight {
		t.Fatal("still in flight")
	}
	// Switching views while a fetch runs does not start another.
	mm := nm.(model)
	nm, cmd = mm.switchTo(viewZones)
	if cmd != nil || nm.(model).view != viewZones {
		t.Fatal("switch while in flight")
	}
	if _, cmd = nm.(model).switchTo(viewZones); cmd != nil {
		t.Fatal("switch to the same view")
	}
}

func TestConnectionStates(t *testing.T) {
	m := newModel(&Client{base: mustURL(t, "http://127.0.0.1:1")}, time.Second)
	m.now = func() time.Time { return testNow }
	mustContain(t, screen(t, m), "Connecting to 127.0.0.1:1")
	nm, _ := m.Update(fetchedMsg{err: errors.New("connection refused")})
	m = nm.(model)
	m.fetchedAt = time.Time{}
	mustContain(t, screen(t, m), "Cannot reach Cerberus", "connection refused", "Retrying")

	// After a good fetch, a failing one marks the data stale but keeps it.
	f := newFakeAPI(t)
	m = testModel(t, f, 100, 30)
	f.failing["alerts"] = true
	m = press(t, m, "3", "r")
	mustContain(t, screen(t, m), "stale: HTTP 500", "s7_program")

	// Sensors without a policy engine, capture or advisories.
	f2 := newFakeAPI(t)
	f2.missing["policy"], f2.missing["captures"], f2.missing["advisories"] = true, true, true
	f2.missing["assets/00:1d:9c:00:00:32/advisories"] = true
	m = testModel(t, f2, 100, 30)
	if m.err != nil {
		t.Fatalf("404s should not count as errors: %v", m.err)
	}
	m = press(t, m, "8")
	mustContain(t, screen(t, m), "policy engine is not enabled")
	m = press(t, m, "9")
	mustContain(t, screen(t, m), "Packet capture is turned off")
}

func TestEmptyStates(t *testing.T) {
	m := newModel(&Client{base: mustURL(t, "http://127.0.0.1:1")}, time.Second)
	m.now = func() time.Time { return testNow }
	m.fetchedAt = testNow
	m.snap.Zones = &zones{}
	m.snap.Baseline = &baseline{}
	m.snap.Baseline.Status.State = "disabled"
	m.snap.Captures = &captures{}
	for v := view(0); v < viewCount; v++ {
		m.view = v
		screen(t, m)
	}
	m.view = viewZones
	mustContain(t, screen(t, m), "No zones are set up")
	m.view = viewBaseline
	mustContain(t, screen(t, m), "turned off")
	m.view = viewDevices
	m.detail, m.advMAC = true, "gone"
	mustContain(t, screen(t, m), "no longer tracked")
	m.view = viewAlerts
	mustContain(t, screen(t, m), "No alert selected")
	m.detail = false
	m = press(t, m, "enter", "a")
	if m.detail || m.prompt.kind != promptNone {
		t.Fatal("enter and a do nothing without alerts")
	}
	m.view = viewDevices
	m = press(t, m, "enter")
	if m.detail {
		t.Fatal("enter without devices")
	}
	m.view = viewBaseline
	m.snap.Baseline = nil
	m = press(t, m, "space")
	screen(t, m)
}

func TestDeviceAdvisoryError(t *testing.T) {
	f := newFakeAPI(t)
	m := testModel(t, f, 120, 40)
	f.failing["assets/00:1d:9c:00:00:32/advisories"] = true
	m = press(t, m, "2", "/")
	m = typeText(t, m, "10.20.0.50")
	m = press(t, m, "enter", "enter")
	mustContain(t, screen(t, m), "could not load: HTTP 500")
	// A late answer for another device is ignored.
	nm, _ := m.Update(advMsg{mac: "other", list: []advisoryMatch{{ID: "X"}}})
	if len(nm.(model).adv) != 0 {
		t.Fatal("stale advisory answer applied")
	}
}

func TestRecordRates(t *testing.T) {
	m := newModel(&Client{base: mustURL(t, "http://x:1")}, 2*time.Second)
	at := testNow
	snap := func(total int) snapshot {
		return snapshot{Summary: &summary{PacketStats: map[string]int{"total": total, "tcp": total}}}
	}
	m.record(snap(100), at)
	m.record(snap(300), at.Add(2*time.Second))
	if got := m.pktRate.latest(); got != 100 {
		t.Fatalf("rate = %v, want 100/s", got)
	}
	m.record(snap(310), at.Add(2500*time.Millisecond)) // too close to the last sample
	if m.pktRate.n != 1 {
		t.Fatal("close sample should be skipped")
	}
	m.record(snap(5), at.Add(5*time.Second)) // counter reset (restart)
	if m.pktRate.n != 1 {
		t.Fatal("reset should not record a negative rate")
	}
	m.record(snapshot{}, at.Add(8*time.Second))
}

func TestClient(t *testing.T) {
	f := newFakeAPI(t)
	f.token = "s3cret-token-0123"
	c, _ := NewClient(f.srv.URL, "wrong", "")
	var s session
	err := c.get(t.Context(), "/api/v1/session", &s)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || !strings.Contains(err.Error(), "invalid bearer token") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(friendlyErr(err), "CERBERUS_API_TOKEN") {
		t.Fatal(friendlyErr(err))
	}
	if friendlyErr(&APIError{Status: 403}) != "your role cannot do this" || friendlyErr(&APIError{Status: 403, Msg: "x"}) != "x" {
		t.Fatal("403 text")
	}
	if (&APIError{Status: 500}).Error() != "HTTP 500" {
		t.Fatal("bare error text")
	}
	c = f.client(t)
	if err := c.get(t.Context(), "/api/v1/session", &s); err != nil || s.Name != "alice" {
		t.Fatalf("session %+v %v", s, err)
	}
	if err := c.post(t.Context(), "/api/v1/alerts/x/ack", map[string]string{"note": "n"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.post(t.Context(), "/api/v1/x", func() {}, nil); err == nil {
		t.Fatal("unencodable body accepted")
	}
	if err := c.get(t.Context(), "/api/v1/session", &[]int{}); err == nil {
		t.Fatal("bad JSON accepted")
	}
	if err := c.get(t.Context(), "/api/v1/nothing", nil); err == nil {
		t.Fatal("404 accepted")
	}
	bad := &Client{base: mustURL(t, "http://127.0.0.1:1"), http: http.DefaultClient}
	if err := bad.get(t.Context(), "/x", nil); err == nil {
		t.Fatal("unreachable host accepted")
	}
}

func TestClientTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"commit":"tls"}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(srv.URL, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	var v version
	if err := c.get(t.Context(), "/api/v1/version", &v); err != nil || v.Commit != "tls" {
		t.Fatalf("%+v %v", v, err)
	}
	// Without the CA the certificate is refused.
	c, _ = NewClient(srv.URL, "", "")
	if err := c.get(t.Context(), "/api/v1/version", &v); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("not a cert"), 0o600)
	if _, err := NewClient(srv.URL, "", junk); err == nil {
		t.Fatal("junk CA accepted")
	}
	if _, err := NewClient(srv.URL, "", filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing CA accepted")
	}
}

func TestBaseURL(t *testing.T) {
	good := map[string]string{
		"":                       "http://127.0.0.1:8080",
		"0.0.0.0:8080":           "http://127.0.0.1:8080",
		"[::]:9000":              "http://127.0.0.1:9000",
		":8080":                  "http://127.0.0.1:8080",
		"sensor.plant:8080":      "http://sensor.plant:8080",
		"https://sensor.plant/":  "https://sensor.plant",
		"http://10.0.0.5:8080/x": "http://10.0.0.5:8080/x",
	}
	for in, want := range good {
		u, err := baseURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q = %v %v, want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"sensor", "ftp://x", "http://", "http://[::1", ":/0//", "x:0", "x:70000", "http://x:99999"} {
		if _, err := baseURL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := NewClient("sensor", "", ""); err == nil {
		t.Error("NewClient accepted a bad address")
	}
}

func FuzzBaseURL(f *testing.F) {
	for _, s := range []string{"", "0.0.0.0:8080", "https://x/", "[::]:1", "a:b:c", "http://%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := baseURL(s)
		if err != nil {
			return
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.HasSuffix(u.Path, "/") {
			t.Fatalf("%q -> %v", s, u)
		}
	})
}

func TestCharts(t *testing.T) {
	h := newHistory(3)
	if h.latest() != 0 || len(h.last(5)) != 0 {
		t.Fatal("empty history")
	}
	for _, v := range []float64{1, 2, 3, 4} {
		h.add(v)
	}
	if got := h.last(5); len(got) != 3 || got[0] != 2 || got[2] != 4 || h.latest() != 4 {
		t.Fatalf("ring = %v", got)
	}
	if s := sparkline([]float64{0, 4, 8}, 5); s != "  ▁▅█" {
		t.Fatalf("sparkline = %q", s)
	}
	if sparkline([]float64{1}, 0) != "" || sparkline([]float64{1, 2, 3}, 2) != "▆█" {
		t.Fatal("sparkline width")
	}
	rows := areaChart([]float64{0, 0.1, 4, 8}, 6, 2)
	if len(rows) != 2 || rows[0] != "     █" || rows[1] != "   ▁██" {
		t.Fatalf("area = %q", rows)
	}
	if areaChart(nil, 0, 2) != nil || len(areaChart([]float64{1, 2, 3}, 2, 1)[0]) == 0 {
		t.Fatal("area edges")
	}
	bars := barChart(map[string]int{"a": 10, "b": 5, "c": 0, "averyveryverylongname": 1}, 3, 40)
	if len(bars) != 3 || !strings.HasPrefix(bars[0], "a") || !strings.Contains(bars[2], "averyvery") {
		t.Fatalf("bars = %q", bars)
	}
	if barChart(nil, 3, 40)[0] != "(none yet)" {
		t.Fatal("empty bars")
	}
	for in, want := range map[int]string{950: "950", 12400: "12.4k", 3100000: "3.1M", 2e9: "2.0G"} {
		if humanInt(in) != want {
			t.Errorf("humanInt(%d) = %s", in, humanInt(in))
		}
	}
	for in, want := range map[int64]string{512: "512 B", 3277: "3.2 KB", 14 << 20: "14.0 MB", 3 << 30: "3.0 GB"} {
		if humanBytes(in) != want {
			t.Errorf("humanBytes(%d) = %s", in, humanBytes(in))
		}
	}
	for in, want := range map[float64]string{2.5: "2.5/s", 42: "42/s", 12400: "12.4k/s", 3.2e6: "3.2M/s"} {
		if rate(in) != want {
			t.Errorf("rate(%v) = %s", in, rate(in))
		}
	}
}

func TestTextHelpers(t *testing.T) {
	if clip("hello", 0) != "" || clip("hello", 3) != "he…" || pad("ab", 4) != "ab  " {
		t.Fatal("clip/pad")
	}
	now := testNow
	for d, want := range map[time.Duration]string{-time.Second: "now", 5 * time.Second: "5s", 3 * time.Minute: "3m", 5 * time.Hour: "5h", 72 * time.Hour: "3d"} {
		if got := ago(now.Add(-d), now); got != want {
			t.Errorf("ago(%v) = %s", d, got)
		}
	}
	if ago(time.Time{}, now) != "never" || clock(time.Time{}, now) != "-" {
		t.Fatal("zero times")
	}
	if clock(now.Add(-time.Minute), now) != "09:59:30" || clock(now.Add(-48*time.Hour), now) != "11-13 10:00" {
		t.Fatal(clock(now.Add(-48*time.Hour), now))
	}
	for _, s := range []string{"high", "critical", "medium", "warning", "low", "info", "other"} {
		_ = severityStyle(s).Render(s)
	}
	if cmpIP("10.0.0.9", "10.0.0.10") >= 0 || cmpIP("a", "b") >= 0 || cmpIP("1.2.3.4", "1.2.3.4") != 0 || atoiSafe("12x") != 12 {
		t.Fatal("cmpIP")
	}
	if got := wrap("one two three four", 9); len(got) != 3 || got[0] != "one two" {
		t.Fatalf("wrap = %q", got)
	}
	if window(0, 10, 3) != 0 || window(9, 10, 3) != 7 || window(5, 4, 10) != 0 {
		t.Fatal("window")
	}
	if roleLabel("plc-ish") != "plc-ish" || roleLabel("") != "-" {
		t.Fatal("role label")
	}
	tb := table{cols: []column{{"A", 5, 0}, {"B", 5, 1}, {"C", 0, 0}}, rows: [][]string{{"1", "2", "3"}}, selected: 0, height: 1}
	if lines := tb.render(16); strings.Contains(ansi.Strip(lines[0]), "B") {
		t.Fatalf("B should hide at 16 columns: %q", lines)
	}
	tb.rows = append(tb.rows, []string{"4", "5", "6"})
	if lines := tb.render(40); !strings.Contains(ansi.Strip(lines[len(lines)-1]), "rows 1-1 of 2") {
		t.Fatalf("scroll hint: %q", lines)
	}
}

func TestMain_Flags(t *testing.T) {
	var out, errb bytes.Buffer
	if Main([]string{"-h"}, &out, &errb) != 0 || !strings.Contains(errb.String(), "Usage: cerberus tui") {
		t.Fatalf("help: %s", errb.String())
	}
	for _, args := range [][]string{{"--bogus"}, {"--interval", "10ms"}, {"--addr", "nope"}, {"--token-file", "/nonexistent/t"}} {
		errb.Reset()
		if Main(args, &out, &errb) != 2 {
			t.Errorf("%v accepted: %s", args, errb.String())
		}
	}
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("tok\n"), 0o600)
	t.Setenv("CERBERUS_HTTP_ADDR", "bad")
	errb.Reset()
	if Main([]string{"--token-file", tok}, &out, &errb) != 2 || !strings.Contains(errb.String(), "bad") {
		t.Fatalf("env address not used: %s", errb.String())
	}
	if envOr("CERBERUS_TUI_UNSET", "d") != "d" {
		t.Fatal("envOr")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Decoding the fixtures with the real types keeps them honest.
func TestFixturesDecode(t *testing.T) {
	f := newFakeAPI(t)
	s, err := fetch(t.Context(), f.client(t), snapshot{}, viewOverview)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s.Policy)
	if !strings.Contains(string(b), "evil.example") {
		t.Fatal("policy fixture not decoded")
	}
}
