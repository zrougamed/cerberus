package monitor

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"

	"github.com/tidwall/buntdb"
)

func newBaselineMonitor(t *testing.T, dbPath string, mutate func(*alerts.FlowBaselineConfig)) *NetworkMonitor {
	t.Helper()
	cfg := alerts.DefaultConfig()
	if mutate != nil {
		mutate(&cfg.FlowBaseline)
	}
	nm, err := NewNetworkMonitorWithAlerts(10, dbPath, cfg)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	return nm
}

var (
	plcWrite = industrial.Message{Protocol: "modbus", Class: industrial.ClassWrite, FunctionName: "write_single_register"}
	plcRead  = industrial.Message{Protocol: "modbus", Class: industrial.ClassRead, FunctionName: "read_coils"}
	hmi      = &models.DeviceInfo{MAC: "02:00:00:00:00:01", IP: "10.0.0.9"}
)

func baselineAlerts(nm *NetworkMonitor) []models.AlertEvent {
	var out []models.AlertEvent
	for _, a := range nm.GetAlerts() {
		if a.Rule == alerts.RuleBaselineNewFlow {
			out = append(out, a)
		}
	}
	return out
}

func TestFlowBaseline_LearnThenAlertOnce(t *testing.T) {
	nm := newBaselineMonitor(t, filepath.Join(t.TempDir(), "t.db"), nil)
	t.Cleanup(func() { _ = nm.Close() })
	start := nm.flowBaseline.meta.StartedAt
	if got := nm.flowBaseline.meta.LearningUntil.Sub(start); got != 168*time.Hour {
		t.Fatalf("learning period = %v", got)
	}

	nm.mu.Lock()
	nm.observeFlow(hmi, plcRead, "10.0.0.9", "10.0.0.5", start.Add(time.Hour))
	nm.observeFlow(hmi, plcRead, "10.0.0.9", "10.0.0.5", start.Add(2*time.Hour))
	after := nm.flowBaseline.meta.LearningUntil.Add(time.Minute)
	nm.observeFlow(hmi, plcRead, "10.0.0.9", "10.0.0.5", after)  // learned
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", after) // new
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", after.Add(time.Minute))
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", after.Add(time.Minute)) // already new
	resp := plcWrite
	resp.Response = true
	nm.observeFlow(hmi, resp, "10.0.0.5", "10.0.0.9", after) // replies are not flows
	nm.mu.Unlock()

	got := baselineAlerts(nm)
	if len(got) != 1 {
		t.Fatalf("alerts = %+v", got)
	}
	if want := "New industrial flow 10.0.0.9 -> 10.0.0.5: Modbus write (not seen while learning)"; got[0].Message != want || got[0].Severity != "medium" {
		t.Fatalf("alert = %+v", got[0])
	}
	flows := nm.GetBaselineFlows("", 0)
	if len(flows) != 2 || flows[0].Status != FlowNew || flows[0].Count != 3 || flows[1].Status != FlowLearned || flows[1].Count != 3 {
		t.Fatalf("flows = %+v", flows)
	}
}

func TestFlowBaseline_StatusApproveForgetRelearn(t *testing.T) {
	nm := newBaselineMonitor(t, filepath.Join(t.TempDir(), "t.db"), nil)
	t.Cleanup(func() { _ = nm.Close() })
	if s := nm.GetBaselineStatus(); s.State != BaselineLearning || s.MaxFlows != 10000 {
		t.Fatalf("status = %+v", s)
	}
	nm.mu.Lock()
	nm.flowBaseline.meta.LearningUntil = time.Now().Add(-time.Hour)
	now := time.Now()
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", now)
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.6", now.Add(time.Second))
	nm.mu.Unlock()

	s := nm.GetBaselineStatus()
	if s.State != BaselineEnforcing || s.New != 2 || s.Learned != 0 {
		t.Fatalf("status = %+v", s)
	}
	newFlows := nm.GetBaselineFlows(FlowNew, 0)
	if len(newFlows) != 2 || newFlows[0].Server != "10.0.0.6" {
		t.Fatalf("new flows (newest first) = %+v", newFlows)
	}
	if n := nm.ApproveFlows([]string{newFlows[0].ID, newFlows[0].ID, "missing"}); n != 1 {
		t.Fatalf("approved = %d", n)
	}
	if s := nm.GetBaselineStatus(); s.Approved != 1 || s.New != 1 {
		t.Fatalf("after approve = %+v", s)
	}
	if n := nm.ForgetFlows([]string{newFlows[1].ID, "missing"}); n != 1 {
		t.Fatalf("forgotten = %d", n)
	}
	// A forgotten flow alerts again next time.
	nm.mu.Lock()
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", time.Now())
	nm.mu.Unlock()
	if len(baselineAlerts(nm)) != 3 {
		t.Fatalf("alerts = %+v", baselineAlerts(nm))
	}
	if !nm.RelearnBaseline() {
		t.Fatal("relearn refused")
	}
	if s := nm.GetBaselineStatus(); s.State != BaselineLearning || s.New+s.Approved+s.Learned != 0 {
		t.Fatalf("after relearn = %+v", s)
	}
	if got := nm.GetBaselineFlows("", 1); len(got) != 0 {
		t.Fatalf("flows after relearn = %+v", got)
	}
}

func TestFlowBaseline_MaxFlowsDrops(t *testing.T) {
	nm := newBaselineMonitor(t, filepath.Join(t.TempDir(), "t.db"), func(c *alerts.FlowBaselineConfig) { c.MaxFlows = 2 })
	t.Cleanup(func() { _ = nm.Close() })
	nm.mu.Lock()
	nm.flowBaseline.meta.LearningUntil = time.Now().Add(-time.Hour)
	for _, server := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		nm.observeFlow(hmi, plcWrite, "10.0.0.9", server, time.Now())
	}
	nm.mu.Unlock()
	if s := nm.GetBaselineStatus(); s.New != 2 || s.Dropped != 2 {
		t.Fatalf("status = %+v", s)
	}
	if len(baselineAlerts(nm)) != 2 {
		t.Fatal("dropped flows must not alert")
	}
	if got := nm.GetBaselineFlows("", 1); len(got) != 1 {
		t.Fatalf("limit ignored: %d", len(got))
	}
}

func TestFlowBaseline_SurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	nm := newBaselineMonitor(t, dbPath, nil)
	meta := nm.flowBaseline.meta
	nm.mu.Lock()
	nm.observeFlow(hmi, plcRead, "10.0.0.9", "10.0.0.5", meta.StartedAt.Add(time.Minute))
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", meta.StartedAt.Add(time.Minute))
	nm.mu.Unlock()
	nm.flushBaseline()
	nm.ForgetFlows([]string{flowID("10.0.0.9", "10.0.0.5", "modbus", "write")})
	if err := nm.Close(); err != nil { // Close flushes the delete
		t.Fatal(err)
	}

	again := newBaselineMonitor(t, dbPath, nil)
	t.Cleanup(func() { _ = again.Close() })
	if !again.flowBaseline.meta.StartedAt.Equal(meta.StartedAt) {
		t.Fatalf("learning restarted: %v vs %v", again.flowBaseline.meta.StartedAt, meta.StartedAt)
	}
	flows := again.GetBaselineFlows("", 0)
	if len(flows) != 1 || flows[0].Class != "read" || flows[0].Count != 1 {
		t.Fatalf("reloaded flows = %+v", flows)
	}
}

func TestFlowBaseline_Disabled(t *testing.T) {
	nm := newBaselineMonitor(t, filepath.Join(t.TempDir(), "t.db"), func(c *alerts.FlowBaselineConfig) { c.Enabled = false })
	t.Cleanup(func() { _ = nm.Close() })
	nm.mu.Lock()
	nm.observeFlow(hmi, plcWrite, "10.0.0.9", "10.0.0.5", time.Now())
	nm.mu.Unlock()
	nm.flushBaseline()
	if s := nm.GetBaselineStatus(); s.State != BaselineDisabled {
		t.Fatalf("status = %+v", s)
	}
	if len(nm.GetBaselineFlows("", 0)) != 0 || nm.ApproveFlows([]string{"x"}) != 0 || nm.ForgetFlows([]string{"x"}) != 0 || nm.RelearnBaseline() {
		t.Fatal("disabled baseline should do nothing")
	}
}

func TestFlowBaseline_TrackEventFeedsBaseline(t *testing.T) {
	nm := newBaselineMonitor(t, filepath.Join(t.TempDir(), "t.db"), nil)
	t.Cleanup(func() { _ = nm.Close() })
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x03, 0, 0, 0, 1))
	nm.TrackEvent(modbusEvent(5, "10.0.0.5", "10.0.0.9", 502, 50000, 1, 0x03, 2, 0, 7))
	flows := nm.GetBaselineFlows("", 0)
	if len(flows) != 1 || flows[0].Client != "10.0.0.9" || flows[0].Status != FlowLearned {
		t.Fatalf("flows = %+v", flows)
	}
}

func TestFlowID_Stable(t *testing.T) {
	t.Parallel()
	a := flowID("10.0.0.9", "10.0.0.5", "modbus", "write")
	if a != flowID("10.0.0.9", "10.0.0.5", "modbus", "write") || a == flowID("10.0.0.5", "10.0.0.9", "modbus", "write") || len(a) != 16 {
		t.Fatalf("id = %s", a)
	}
}

func TestFlowBaseline_CorruptStoredRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	nm := newBaselineMonitor(t, dbPath, nil)
	_ = nm.db.Update(func(tx *buntdb.Tx) error {
		_, _, _ = tx.Set(flowMetaKey, "{broken", nil)
		_, _, _ = tx.Set(flowKeyPrefix+"0000000000000001", "{broken", nil)
		_, _, _ = tx.Set(flowKeyPrefix+"0000000000000002", `{"id":"0000000000000002","status":"learned"}`, nil)
		return nil
	})
	nm.flowBaseline.metaDirty = false
	_ = nm.Close()

	again := newBaselineMonitor(t, dbPath, nil)
	t.Cleanup(func() { _ = again.Close() })
	if again.flowBaseline.meta.StartedAt.IsZero() {
		t.Fatal("corrupt header should start a fresh learning period")
	}
	// A fresh learning period drops whatever flows were stored.
	if n := len(again.GetBaselineFlows("", 0)); n != 0 {
		t.Fatalf("flows kept after restart of learning: %d", n)
	}
}
