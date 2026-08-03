package notify

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateDisabled(t *testing.T) {
	t.Parallel()
	if err := Validate(Config{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEnabledNeedsSink(t *testing.T) {
	t.Parallel()
	cfg := Config{Enabled: true, MinSeverity: "low"}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected New to require a sink")
	}
}

func TestWebhookDelivery(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := New(Config{
		Enabled:     true,
		MinSeverity: "low",
		Webhook:     WebhookConfig{URL: srv.URL, TimeoutSeconds: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.Notify(Event{
		Kind:     KindRule,
		Severity: "high",
		Title:    "test",
		Message:  "hello",
		Rule:     "dns_query_volume",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := got.Load(); v != nil {
			var e Event
			if err := json.Unmarshal(v.([]byte), &e); err != nil {
				t.Fatal(err)
			}
			if e.Kind != KindRule || e.Message != "hello" || e.Rule != "dns_query_volume" {
				t.Fatalf("unexpected payload: %+v", e)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("webhook not received")
}

func TestSlackDelivery(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := New(Config{
		Enabled:     true,
		MinSeverity: "low",
		Slack:       SlackConfig{WebhookURL: srv.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.Notify(Event{
		Kind:      KindRule,
		Severity:  "high",
		Title:     "DNS spike",
		Message:   "DNS queries exceeded threshold",
		DeviceMAC: "AA:BB:CC:DD:EE:FF",
		Rule:      "dns_query_volume",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := got.Load(); v != nil {
			var payload map[string]any
			if err := json.Unmarshal(v.([]byte), &payload); err != nil {
				t.Fatal(err)
			}
			text, _ := payload["text"].(string)
			if !strings.Contains(text, "DNS spike") {
				t.Fatalf("slack text missing title: %v", payload)
			}
			blocks, ok := payload["blocks"].([]any)
			if !ok || len(blocks) < 2 {
				t.Fatalf("expected slack blocks: %v", payload)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slack webhook not received")
}

func TestTeamsAdaptiveDelivery(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := New(Config{
		Enabled:     true,
		MinSeverity: "low",
		Teams: TeamsConfig{
			WebhookURL: srv.URL,
			Format:     TeamsFormatAdaptive,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.Notify(Event{
		Kind:     KindAnomaly,
		Severity: "medium",
		Title:    "Traffic anomaly detected",
		Message:  "SYN rate jumped",
		Score:    4.2,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := got.Load(); v != nil {
			var payload map[string]any
			if err := json.Unmarshal(v.([]byte), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["type"] != "message" {
				t.Fatalf("expected Teams message wrapper: %v", payload)
			}
			atts, ok := payload["attachments"].([]any)
			if !ok || len(atts) != 1 {
				t.Fatalf("expected one attachment: %v", payload)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("teams webhook not received")
}

func TestTeamsMessageCardPayload(t *testing.T) {
	t.Parallel()
	payload := teamsPayload(Event{
		Kind:     KindNewDevice,
		Severity: "low",
		Title:    "New device detected",
		Message:  "mac=aa:bb",
	}, TeamsFormatMessageCard)
	if payload["@type"] != "MessageCard" {
		t.Fatalf("expected MessageCard: %v", payload)
	}
}

func TestMinSeverityFilter(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d, err := New(Config{
		Enabled:     true,
		MinSeverity: "high",
		Webhook:     WebhookConfig{URL: srv.URL, TimeoutSeconds: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.Notify(Event{Kind: KindRule, Severity: "low", Title: "skip", Message: "no"})
	d.Notify(Event{Kind: KindRule, Severity: "high", Title: "keep", Message: "yes"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if count.Load() >= 1 {
			time.Sleep(50 * time.Millisecond)
			if count.Load() != 1 {
				t.Fatalf("expected 1 delivery, got %d", count.Load())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no webhook received")
}

func TestSyslogUDPDelivery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	d, err := New(Config{
		Enabled:     true,
		MinSeverity: "low",
		Syslog: SyslogConfig{
			Network: "udp",
			Address: pc.LocalAddr().String(),
			Tag:     "cerberus-test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	d.Notify(Event{
		Kind:     KindNewDevice,
		Severity: "medium",
		Title:    "New device detected",
		Message:  "mac=aa:bb:cc",
	})

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("syslog read: %v", err)
	}
	msg := string(buf[:n])
	if !strings.Contains(msg, "new_device") || !strings.Contains(msg, "New device detected") {
		t.Fatalf("unexpected syslog message: %q", msg)
	}
}

func TestValidateSlackAndTeamsURLs(t *testing.T) {
	t.Parallel()
	if err := Validate(Config{
		Enabled: true,
		Slack:   SlackConfig{WebhookURL: "not-a-url"},
	}); err == nil {
		t.Fatal("expected slack url validation error")
	}
	if err := Validate(Config{
		Enabled: true,
		Teams:   TeamsConfig{WebhookURL: "https://example.com", Format: "nope"},
	}); err == nil {
		t.Fatal("expected teams format validation error")
	}
}
