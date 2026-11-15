package monitor

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func TestAckAlert(t *testing.T) {
	nm, err := NewNetworkMonitorWithAlerts(10, filepath.Join(t.TempDir(), "t.db"), alerts.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	nm.mu.Lock()
	nm.appendAlert(models.AlertEvent{ID: "a1", Rule: "modbus_write"})
	nm.appendAlert(models.AlertEvent{ID: "a2", Rule: "s7_control"})
	nm.mu.Unlock()

	now := time.Date(2026, 11, 15, 9, 30, 0, 0, time.FixedZone("CET", 3600))
	got, err := nm.AckAlert("a2", "alice", "  planned stop  ", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.AckedBy != "alice" || got.Note != "planned stop" || got.AckedAt == nil || !got.AckedAt.Equal(now) || got.AckedAt.Location() != time.UTC {
		t.Fatalf("ack = %+v", got)
	}
	list := nm.GetAlerts()
	var stored models.AlertEvent
	for _, a := range list {
		if a.ID == "a2" {
			stored = a
		}
	}
	if stored.AckedBy != "alice" {
		t.Fatalf("ack not kept in the history: %+v", list)
	}

	// A second acknowledgement replaces the first.
	if got, _ = nm.AckAlert("a2", "bob", "", now.Add(time.Minute)); got.AckedBy != "bob" || got.Note != "" {
		t.Fatalf("re-ack = %+v", got)
	}
	if _, err := nm.AckAlert("missing", "alice", "", now); !errors.Is(err, ErrUnknownAlert) {
		t.Fatalf("unknown id: %v", err)
	}
	// The limit counts characters, not bytes.
	if _, err := nm.AckAlert("a1", "alice", strings.Repeat("é", maxNoteLen), now); err != nil {
		t.Fatalf("500 characters refused: %v", err)
	}
	if _, err := nm.AckAlert("a1", "alice", strings.Repeat("x", maxNoteLen+1), now); err == nil {
		t.Fatal("over-long note accepted")
	}
}
