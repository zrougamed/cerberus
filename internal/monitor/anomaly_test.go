package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func TestAnomalyDetectorEmitsAnomalyAfterBaseline(t *testing.T) {
	ad := newAnomalyDetector(alerts.DefaultConfig().Anomaly)
	ad.window = 50 * time.Millisecond
	ad.baselineNeeded = 3
	start := time.Now()

	// Build baseline windows
	for w := 0; w < 3; w++ {
		for i := 0; i < 5; i++ {
			ad.observe(start.Add(time.Duration(w)*ad.window+time.Duration(i)*time.Millisecond), &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP, DstPort: 443}, "aa:bb")
		}
		ad.observe(start.Add(time.Duration(w+1)*ad.window), &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP, DstPort: 443}, "aa:bb")
	}

	// Inject spiky anomalous window
	for i := 0; i < 100; i++ {
		ad.observe(start.Add(4*ad.window+time.Duration(i)*time.Microsecond), &models.NetworkEvent{EventType: models.EVENT_TYPE_DNS, DstPort: 60000}, "cc:dd")
	}
	ad.observe(start.Add(5*ad.window), &models.NetworkEvent{EventType: models.EVENT_TYPE_DNS, DstPort: 60001}, "cc:dd")

	s := ad.status()
	if s.Status != "active" {
		t.Fatalf("expected active status, got %q", s.Status)
	}
	if len(s.RecentAlerts) == 0 {
		t.Fatalf("expected anomaly alerts to be produced")
	}
	a := s.RecentAlerts[0]
	if a.Summary == "" {
		t.Fatal("expected plain-language summary")
	}
	if a.Detail == "" {
		t.Fatal("expected technical detail string")
	}
	if a.Summary == a.Detail {
		t.Fatal("plain summary and technical detail should differ")
	}
}

func TestBuildPlainLanguageSummaryNoAnomaly(t *testing.T) {
	t.Parallel()
	c := []models.AnomalyContribution{
		{Feature: "packet_rate", Label: "Events per second (all types)", Value: 10, BaselineMedian: 9, RobustZ: 0.5},
	}
	s := buildPlainLanguageSummary(c, false, 2.0, 3.5)
	if s == "" {
		t.Fatal("expected summary")
	}
	if !strings.Contains(s, "No anomaly") || !strings.Contains(s, "2.00") {
		t.Fatalf("unexpected no-anomaly text: %q", s)
	}
}

func TestBuildPlainLanguageSummaryAnomalyMultiPhrase(t *testing.T) {
	t.Parallel()
	c := []models.AnomalyContribution{
		{Feature: "tcp_syn_rate", Label: "TCP SYN", Value: 100, BaselineMedian: 0, RobustZ: 8},
		{Feature: "packet_rate", Label: "Events per second (all types)", Value: 2000, BaselineMedian: 80, RobustZ: 8},
	}
	s := buildPlainLanguageSummary(c, true, 6.0, 3.5)
	if !strings.Contains(s, "unusual") {
		t.Fatalf("expected lead-in, got: %q", s)
	}
	if !strings.Contains(s, "SYN") && !strings.Contains(strings.ToLower(s), "handshake") {
		t.Fatalf("expected SYN / handshake wording, got: %q", s)
	}
}
