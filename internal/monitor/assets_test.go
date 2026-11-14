package monitor

import (
	"errors"
	"testing"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"

	"github.com/tidwall/buntdb"
)

func stats(requests, responses int, ops map[string]int, peers ...string) *models.IndustrialStats {
	return &models.IndustrialStats{Requests: requests, Responses: responses, Operations: ops, Peers: peers}
}

func TestInferRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		d    models.DeviceInfo
		want string
	}{
		{"nothing", models.DeviceInfo{}, ""},
		{"plc answers modbus", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"modbus": stats(0, 40, nil)}}, RoleController},
		{"hmi polls one plc", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"modbus": stats(40, 0, map[string]int{"read": 40}, "10.0.0.5")}}, RoleHMI},
		{"scada polls three", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{
			"modbus": stats(90, 0, map[string]int{"read": 90}, "10.0.0.5", "10.0.0.6"),
			"dnp3":   stats(10, 0, map[string]int{"read": 10}, "10.0.0.7"),
		}}, RoleSCADAServer},
		{"writes alone stay hmi", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"s7comm": stats(5, 0, map[string]int{"write": 5}, "10.0.0.5")}}, RoleHMI},
		{"download makes an engineering workstation", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"s7comm": stats(5, 0, map[string]int{"read": 4, "program": 1}, "10.0.0.5")}}, RoleEngineeringWorkstation},
		{"mqtt broker is not a controller", models.DeviceInfo{Industrial: map[string]*models.IndustrialStats{"mqtt": stats(0, 50, nil)}}, ""},
		{"bacnet device from i-am", models.DeviceInfo{Asset: &models.AssetInfo{Source: "bacnet"}}, RoleController},
		{"enip asset alone", models.DeviceInfo{Asset: &models.AssetInfo{Source: "enip"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := InferRole(&tt.d); got != tt.want {
				t.Fatalf("InferRole = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordAsset_ChangeRaisesAlert(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	d := &models.DeviceInfo{MAC: "02:00:00:00:00:08", IP: "10.0.0.80"}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	id := &industrial.Identity{Vendor: "Rockwell Automation", Model: "1756-L83E", Firmware: "32.011", Serial: "c0ffee01"}

	nm.mu.Lock()
	nm.recordAsset(d, "enip", id, t0)
	nm.recordAsset(d, "enip", id, t0.Add(time.Minute)) // same identity
	upgraded := *id
	upgraded.Firmware = "33.011"
	nm.recordAsset(d, "enip", &upgraded, t0.Add(2*time.Minute))
	nm.mu.Unlock()

	got := nm.GetAlerts()
	if len(got) != 1 || got[0].Rule != alerts.RuleAssetChanged || got[0].Severity != "high" {
		t.Fatalf("alerts = %+v", got)
	}
	if want := "Device 10.0.0.80 reported a new identity over EtherNet/IP: firmware 32.011 -> 33.011"; got[0].Message != want {
		t.Fatalf("message = %q, want %q", got[0].Message, want)
	}
	if d.Asset.Firmware != "33.011" || !d.Asset.UpdatedAt.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("asset = %+v", d.Asset)
	}
}

func TestRecordAsset_OtherSourceOnlyFillsGaps(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	d := &models.DeviceInfo{MAC: "02:00:00:00:00:09"}
	nm.mu.Lock()
	nm.recordAsset(d, "enip", &industrial.Identity{Vendor: "Rockwell Automation", Model: "1756-L83E"}, time.Now())
	nm.recordAsset(d, "modbus", &industrial.Identity{Vendor: "Other", Model: "Other", Firmware: "1.0", Serial: "s", DeviceType: "t"}, time.Now())
	nm.mu.Unlock()
	want := models.AssetInfo{Vendor: "Rockwell Automation", Model: "1756-L83E", Firmware: "1.0", Serial: "s", DeviceType: "t", Source: "enip"}
	got := *d.Asset
	got.UpdatedAt = time.Time{}
	if got != want {
		t.Fatalf("asset = %+v, want %+v", got, want)
	}
	if len(nm.GetAlerts()) != 0 {
		t.Fatal("cross-protocol differences must not alert")
	}
}

func TestRecordAsset_ChangeAlertDisabled(t *testing.T) {
	nm := newIndustrialMonitor(t, func(c *alerts.IndustrialConfig) { c.AssetChanged.Enabled = false })
	d := &models.DeviceInfo{MAC: "02:00:00:00:00:0a"}
	nm.mu.Lock()
	nm.recordAsset(d, "modbus", &industrial.Identity{Model: "A"}, time.Now())
	nm.recordAsset(d, "modbus", &industrial.Identity{Model: "B"}, time.Now())
	nm.mu.Unlock()
	if len(nm.GetAlerts()) != 0 || d.Asset.Model != "B" {
		t.Fatalf("alerts = %+v asset = %+v", nm.GetAlerts(), d.Asset)
	}
}

func TestSetRoleOverride(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	nm.TrackEvent(modbusEvent(1, "10.0.0.9", "10.0.0.5", 50000, 502, 1, 0x03, 0, 0, 0, 1))
	mac := "02:00:00:00:00:01"

	if err := nm.SetRoleOverride(mac, RoleHistorian); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := nm.GetStats()[mac].RoleOverride; got != RoleHistorian {
		t.Fatalf("override = %q", got)
	}
	// Stored immediately: survives the device leaving the cache.
	nm.Cache.Purge()
	if d := nm.loadDevice(mac); d == nil || d.RoleOverride != RoleHistorian {
		t.Fatalf("stored record = %+v", d)
	}
	// Setting on an evicted device reloads it.
	if err := nm.SetRoleOverride(mac, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := nm.GetStats()[mac].RoleOverride; got != "" {
		t.Fatalf("override after clear = %q", got)
	}

	if err := nm.SetRoleOverride(mac, "admin"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("invalid role err = %v", err)
	}
	if err := nm.SetRoleOverride("02:00:00:00:00:99", RoleHMI); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown device err = %v", err)
	}
}

func TestLoadDevice_MissingAndCorrupt(t *testing.T) {
	nm := newIndustrialMonitor(t, nil)
	if err := nm.storeDevice(&models.DeviceInfo{MAC: "02:00:00:00:00:0b"}); err != nil {
		t.Fatal(err)
	}
	if d := nm.loadDevice("02:00:00:00:00:0b"); d == nil {
		t.Fatal("stored device not loaded")
	}
	if d := nm.loadDevice("02:00:00:00:00:0c"); d != nil {
		t.Fatalf("missing device loaded: %+v", d)
	}
	err := nm.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("02:00:00:00:00:0d", "{not json", nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := nm.loadDevice("02:00:00:00:00:0d"); d != nil {
		t.Fatalf("corrupt record loaded: %+v", d)
	}
}
