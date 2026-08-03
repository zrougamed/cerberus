// Package notify delivers outbound alert notifications (webhook, Slack, Teams, syslog).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event kinds that can be routed to sinks.
const (
	KindRule      = "rule"
	KindAnomaly   = "anomaly"
	KindNewDevice = "new_device"
)

// Teams webhook payload formats.
const (
	TeamsFormatMessageCard = "message_card" // classic Office 365 connector
	TeamsFormatAdaptive    = "adaptive"     // Power Automate / Workflows (default)
)

// Event is a sink-agnostic notification payload.
type Event struct {
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	DeviceMAC  string    `json:"device_mac,omitempty"`
	DeviceIP   string    `json:"device_ip,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Score      float64   `json:"score,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// WebhookConfig posts the raw Event JSON to a generic HTTP endpoint.
type WebhookConfig struct {
	URL            string `yaml:"url" json:"url"`
	TimeoutSeconds int    `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// SlackConfig posts Slack Block Kit messages to an Incoming Webhook.
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
}

// TeamsConfig posts to a Microsoft Teams Incoming Webhook or Workflow URL.
type TeamsConfig struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
	// Format is message_card (legacy connector) or adaptive (Power Automate; default).
	Format string `yaml:"format" json:"format"`
}

// SyslogConfig writes RFC5424-compatible messages via log/syslog.
type SyslogConfig struct {
	Network string `yaml:"network" json:"network"` // udp, tcp, unix, unixgram
	Address string `yaml:"address" json:"address"`
	Tag     string `yaml:"tag" json:"tag"`
}

// Config controls which events are forwarded and to which sinks.
type Config struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	MinSeverity string        `yaml:"min_severity" json:"min_severity"`
	Kinds       []string      `yaml:"kinds" json:"kinds"` // empty = all kinds
	Webhook     WebhookConfig `yaml:"webhook" json:"webhook"`
	Slack       SlackConfig   `yaml:"slack" json:"slack"`
	Teams       TeamsConfig   `yaml:"teams" json:"teams"`
	Syslog      SyslogConfig  `yaml:"syslog" json:"syslog"`
}

// Dispatcher fans events to configured sinks asynchronously.
type Dispatcher struct {
	cfg    Config
	ch     chan Event
	client *http.Client
	wg     sync.WaitGroup
	once   sync.Once
}

// New returns a dispatcher when notifications are enabled and at least one sink
// is configured. Returns nil when disabled (no-op for callers).
func New(cfg Config) (*Dispatcher, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if !hasSink(cfg) {
		return nil, fmt.Errorf("notifications enabled but no sink configured (webhook, slack, teams, or syslog)")
	}
	timeout := cfg.Webhook.TimeoutSeconds
	if timeout <= 0 {
		timeout = 5
	}
	d := &Dispatcher{
		cfg: cfg,
		ch:  make(chan Event, 256),
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
	d.wg.Add(1)
	go d.loop()
	return d, nil
}

// Notify enqueues an event. Drops when the buffer is full (never blocks callers).
func (d *Dispatcher) Notify(e Event) {
	if d == nil {
		return
	}
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now()
	}
	if e.Severity == "" {
		e.Severity = "medium"
	}
	if !d.allowsKind(e.Kind) || !d.allowsSeverity(e.Severity) {
		return
	}
	select {
	case d.ch <- e:
	default:
		log.Printf("notify: dropping %s event (buffer full)", e.Kind)
	}
}

// Close stops the worker and waits for in-flight deliveries.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		close(d.ch)
	})
	d.wg.Wait()
}

func (d *Dispatcher) loop() {
	defer d.wg.Done()
	var syslogWriter *syslog.Writer
	if d.cfg.Syslog.Address != "" {
		tag := d.cfg.Syslog.Tag
		if tag == "" {
			tag = "cerberus"
		}
		network := d.cfg.Syslog.Network
		if network == "" {
			network = "udp"
		}
		w, err := syslog.Dial(network, d.cfg.Syslog.Address, syslog.LOG_ALERT|syslog.LOG_DAEMON, tag)
		if err != nil {
			log.Printf("notify: syslog dial failed: %v", err)
		} else {
			syslogWriter = w
			defer syslogWriter.Close()
		}
	}
	for e := range d.ch {
		if d.cfg.Webhook.URL != "" {
			if err := d.postJSON(d.cfg.Webhook.URL, e); err != nil {
				log.Printf("notify: webhook failed: %v", err)
			}
		}
		if d.cfg.Slack.WebhookURL != "" {
			if err := d.postJSON(d.cfg.Slack.WebhookURL, slackPayload(e)); err != nil {
				log.Printf("notify: slack failed: %v", err)
			}
		}
		if d.cfg.Teams.WebhookURL != "" {
			payload := teamsPayload(e, d.cfg.Teams.Format)
			if err := d.postJSON(d.cfg.Teams.WebhookURL, payload); err != nil {
				log.Printf("notify: teams failed: %v", err)
			}
		}
		if syslogWriter != nil {
			if err := writeSyslog(syslogWriter, e); err != nil {
				log.Printf("notify: syslog write failed: %v", err)
			}
		}
	}
}

func (d *Dispatcher) postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cerberus-Network-Monitor/1.0")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func writeSyslog(w *syslog.Writer, e Event) error {
	msg := fmt.Sprintf("cerberus kind=%s severity=%s title=%q message=%q",
		e.Kind, e.Severity, e.Title, e.Message)
	if e.DeviceMAC != "" {
		msg += fmt.Sprintf(" mac=%s", e.DeviceMAC)
	}
	if e.DeviceIP != "" {
		msg += fmt.Sprintf(" ip=%s", e.DeviceIP)
	}
	if e.Rule != "" {
		msg += fmt.Sprintf(" rule=%s", e.Rule)
	}
	if e.Score > 0 {
		msg += fmt.Sprintf(" score=%.2f", e.Score)
	}
	switch strings.ToLower(e.Severity) {
	case "high":
		return w.Alert(msg)
	case "medium":
		return w.Warning(msg)
	default:
		return w.Info(msg)
	}
}

func (d *Dispatcher) allowsKind(kind string) bool {
	if len(d.cfg.Kinds) == 0 {
		return true
	}
	for _, k := range d.cfg.Kinds {
		if strings.EqualFold(strings.TrimSpace(k), kind) {
			return true
		}
	}
	return false
}

func (d *Dispatcher) allowsSeverity(sev string) bool {
	return severityRank(sev) >= severityRank(d.cfg.MinSeverity)
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low", "":
		return 1
	default:
		return 0
	}
}

func hasSink(cfg Config) bool {
	return strings.TrimSpace(cfg.Webhook.URL) != "" ||
		strings.TrimSpace(cfg.Slack.WebhookURL) != "" ||
		strings.TrimSpace(cfg.Teams.WebhookURL) != "" ||
		strings.TrimSpace(cfg.Syslog.Address) != ""
}

func httpURL(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// Validate checks notification config. Disabled configs are always valid.
func Validate(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.MinSeverity != "" && severityRank(cfg.MinSeverity) == 0 {
		return fmt.Errorf("notifications.min_severity: unknown %q (want low|medium|high)", cfg.MinSeverity)
	}
	for i, k := range cfg.Kinds {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case KindRule, KindAnomaly, KindNewDevice:
		default:
			return fmt.Errorf("notifications.kinds[%d]: unknown %q (want rule|anomaly|new_device)", i, k)
		}
	}
	if cfg.Webhook.URL != "" && !httpURL(cfg.Webhook.URL) {
		return fmt.Errorf("notifications.webhook.url must be http(s)")
	}
	if cfg.Webhook.TimeoutSeconds < 0 {
		return fmt.Errorf("notifications.webhook.timeout_seconds must be >= 0")
	}
	if cfg.Slack.WebhookURL != "" && !httpURL(cfg.Slack.WebhookURL) {
		return fmt.Errorf("notifications.slack.webhook_url must be http(s)")
	}
	if cfg.Teams.WebhookURL != "" && !httpURL(cfg.Teams.WebhookURL) {
		return fmt.Errorf("notifications.teams.webhook_url must be http(s)")
	}
	if cfg.Teams.Format != "" {
		switch strings.ToLower(strings.TrimSpace(cfg.Teams.Format)) {
		case TeamsFormatMessageCard, TeamsFormatAdaptive:
		default:
			return fmt.Errorf("notifications.teams.format: unknown %q (want message_card|adaptive)", cfg.Teams.Format)
		}
	}
	if cfg.Syslog.Address != "" {
		switch strings.ToLower(cfg.Syslog.Network) {
		case "", "udp", "tcp", "unix", "unixgram":
		default:
			return fmt.Errorf("notifications.syslog.network: unknown %q (want udp|tcp|unix|unixgram)", cfg.Syslog.Network)
		}
	}
	return nil
}
