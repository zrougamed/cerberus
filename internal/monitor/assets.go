package monitor

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"
)

// Asset roles. Inference only produces the first four; the rest exist so
// an operator can label what traffic cannot tell apart.
const (
	RoleController             = "controller"
	RoleHMI                    = "hmi"
	RoleSCADAServer            = "scada_server"
	RoleEngineeringWorkstation = "engineering_workstation"
	RoleGateway                = "gateway"
	RoleHistorian              = "historian"
	RoleOther                  = "other"
)

// AssetRoles lists the values SetRoleOverride accepts (plus "" to clear).
var AssetRoles = []string{
	RoleController, RoleHMI, RoleSCADAServer, RoleEngineeringWorkstation,
	RoleGateway, RoleHistorian, RoleOther,
}

// ErrUnknownDevice is returned for a MAC the monitor has never seen.
var ErrUnknownDevice = errors.New("unknown device")

// ErrInvalidRole is returned for a role outside AssetRoles.
var ErrInvalidRole = errors.New("invalid role")

// scadaPeerThreshold is how many distinct controllers a client must talk
// to before it is called a SCADA server rather than an HMI panel.
const scadaPeerThreshold = 3

// roleProtocols are the control protocols whose client/server split says
// something about a device's role. MQTT and OPC UA are left out: a broker
// or an OPC UA server answers requests without being a controller.
var roleProtocols = []string{
	industrial.ProtocolModbus, industrial.ProtocolS7, industrial.ProtocolDNP3,
	industrial.ProtocolENIP, industrial.ProtocolBACnet, industrial.ProtocolIEC104,
}

// InferRole guesses an asset role from a device's industrial traffic. It
// returns "" when there is nothing to go on.
func InferRole(d *models.DeviceInfo) string {
	var requests, responses, risky int
	peers := map[string]struct{}{}
	for _, proto := range roleProtocols {
		s := d.Industrial[proto]
		if s == nil {
			continue
		}
		requests += s.Requests
		responses += s.Responses
		for _, class := range []industrial.Class{industrial.ClassProgram, industrial.ClassControl, industrial.ClassDiagnostic} {
			risky += s.Operations[string(class)]
		}
		if s.Requests > 0 {
			for _, p := range s.Peers {
				peers[p] = struct{}{}
			}
		}
	}
	switch {
	case risky > 0:
		return RoleEngineeringWorkstation
	case requests > 0 && len(peers) >= scadaPeerThreshold:
		return RoleSCADAServer
	case requests > 0:
		return RoleHMI
	case responses > 0:
		return RoleController
	case d.Asset != nil && d.Asset.Source == industrial.ProtocolBACnet:
		return RoleController
	}
	return ""
}

// recordAsset stores the identity a device announced. A new identity from
// the same protocol replaces the old one and raises asset_changed when the
// model, firmware or serial differ; one from another protocol only fills
// fields that are still empty. Caller holds nm.mu.
func (nm *NetworkMonitor) recordAsset(device *models.DeviceInfo, protocol string, id *industrial.Identity, now time.Time) {
	next := models.AssetInfo{
		Vendor: id.Vendor, Model: id.Model, Firmware: id.Firmware, Serial: id.Serial,
		DeviceType: id.DeviceType, Source: protocol, UpdatedAt: now,
	}
	prev := device.Asset
	if prev == nil {
		device.Asset = &next
		return
	}
	if prev.Source != protocol {
		fillEmpty(&prev.Vendor, next.Vendor)
		fillEmpty(&prev.Model, next.Model)
		fillEmpty(&prev.Firmware, next.Firmware)
		fillEmpty(&prev.Serial, next.Serial)
		fillEmpty(&prev.DeviceType, next.DeviceType)
		return
	}
	var changes []string
	for _, f := range []struct{ name, old, new string }{
		{"model", prev.Model, next.Model},
		{"firmware", prev.Firmware, next.Firmware},
		{"serial", prev.Serial, next.Serial},
	} {
		if f.old != "" && f.new != "" && f.old != f.new {
			changes = append(changes, fmt.Sprintf("%s %s -> %s", f.name, f.old, f.new))
		}
	}
	device.Asset = &next
	if len(changes) == 0 || !nm.alertConfig.Industrial.AssetChanged.Enabled {
		return
	}
	nm.appendAlert(models.AlertEvent{
		ID:         fmt.Sprintf("%d-%s-%s", now.UnixNano(), device.MAC, alerts.RuleAssetChanged),
		DeviceMAC:  device.MAC,
		DeviceIP:   device.IP,
		Vendor:     device.Vendor,
		Rule:       alerts.RuleAssetChanged,
		Severity:   nm.alertConfig.Industrial.AssetChanged.Severity,
		Message:    fmt.Sprintf("Device %s reported a new identity over %s: %s", device.IP, protocolLabels[protocol], strings.Join(changes, ", ")),
		ObservedAt: now,
	})
}

func fillEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// SetRoleOverride sets or clears (role "") the operator role of a device.
// The change is stored with the device and survives restarts.
func (nm *NetworkMonitor) SetRoleOverride(mac, role string) error {
	if role != "" && !slices.Contains(AssetRoles, role) {
		return fmt.Errorf("%w %q", ErrInvalidRole, role)
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()
	device, ok := nm.Cache.Get(mac)
	if !ok {
		device = nm.loadDevice(mac)
		if device == nil {
			return fmt.Errorf("%w %s", ErrUnknownDevice, mac)
		}
		nm.Cache.Add(mac, device)
	}
	device.RoleOverride = role
	return nm.storeDevice(device)
}
