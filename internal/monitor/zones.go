package monitor

import (
	"fmt"
	"maps"
	"net/netip"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
	ipProtoTCP = 6
	// maxZoneAlertKeys bounds the re-alert state, same policy as the
	// watchlists.
	maxZoneAlertKeys = 4096
)

// ZoneSummary describes the configured segmentation and what crossed it.
type ZoneSummary struct {
	Zones      []ZoneInfo        `json:"zones"`
	Conduits   []alerts.Conduit  `json:"conduits"`
	Violations map[string]uint64 `json:"violations"` // "from>to" -> packets
}

// ZoneInfo is a zone with the number of known devices in it.
type ZoneInfo struct {
	alerts.Zone
	Devices int `json:"devices"`
}

// checkZones records the device's zone and raises zone_no_conduit or
// zone_level_skip for traffic between two zones that no conduit allows.
// Traffic to or from an address outside every zone is not judged. Caller
// holds nm.mu.
func (nm *NetworkMonitor) checkZones(device *models.DeviceInfo, evt *models.NetworkEvent, srcIP, dstIP, protocol string, now time.Time) {
	if nm.zones == nil {
		return
	}
	src, _ := netip.ParseAddr(srcIP)
	dst, _ := netip.ParseAddr(dstIP)
	from, to := nm.zones.Zone(src), nm.zones.Zone(dst)
	device.Zone = ""
	if from != nil {
		device.Zone = from.ID
	}
	if from == nil || to == nil || from.ID == to.ID {
		return
	}
	synOnly := evt.Protocol == ipProtoTCP && evt.TCPFlags&tcpFlagSYN != 0 && evt.TCPFlags&tcpFlagACK == 0
	if nm.zones.Allowed(from.ID, to.ID, evt.SrcPort, evt.DstPort, synOnly) {
		return
	}
	nm.zoneViolations[from.ID+">"+to.ID]++

	levels := from.Level - to.Level
	if levels < 0 {
		levels = -levels
	}
	rule, ruleID := nm.alertConfig.Segmentation.NoConduit, alerts.RuleZoneNoConduit
	if levels > 1 {
		rule, ruleID = nm.alertConfig.Segmentation.LevelSkip, alerts.RuleZoneLevelSkip
	}
	if !rule.Enabled {
		return
	}
	key := from.ID + "|" + to.ID + "|" + srcIP + "|" + dstIP
	if last, ok := nm.zoneLast[key]; ok && now.Sub(last) < time.Duration(rule.RealertSeconds)*time.Second {
		return
	}
	nm.pruneZoneState(now)
	nm.zoneLast[key] = now

	flow := fmt.Sprintf("%s %s -> %s", protocol, srcIP, dstIP)
	if evt.SrcPort != 0 || evt.DstPort != 0 {
		flow = fmt.Sprintf("%s %s:%d -> %s:%d", protocol, srcIP, evt.SrcPort, dstIP, evt.DstPort)
	}
	msg := fmt.Sprintf("No conduit for %s from %s (level %d) to %s (level %d)", flow, from.Name, from.Level, to.Name, to.Level)
	if levels > 1 {
		msg += fmt.Sprintf(", skips %d levels", levels-1)
	}
	nm.appendAlert(models.AlertEvent{
		ID:         fmt.Sprintf("%d-%s-%s", now.UnixNano(), device.MAC, ruleID),
		DeviceMAC:  device.MAC,
		DeviceIP:   device.IP,
		Vendor:     device.Vendor,
		Rule:       ruleID,
		Severity:   rule.Severity,
		Message:    msg,
		ObservedAt: now,
	})
}

func (nm *NetworkMonitor) pruneZoneState(now time.Time) {
	if len(nm.zoneLast) < maxZoneAlertKeys {
		return
	}
	longest := time.Duration(max(nm.alertConfig.Segmentation.NoConduit.RealertSeconds,
		nm.alertConfig.Segmentation.LevelSkip.RealertSeconds)) * time.Second
	for k, t := range nm.zoneLast {
		if now.Sub(t) >= longest {
			delete(nm.zoneLast, k)
		}
	}
	if len(nm.zoneLast) >= maxZoneAlertKeys {
		clear(nm.zoneLast)
	}
}

// GetZoneSummary returns the zones with device counts, the conduits and
// the violation counters. Zones is empty when segmentation is not set up.
func (nm *NetworkMonitor) GetZoneSummary() ZoneSummary {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	out := ZoneSummary{Zones: []ZoneInfo{}, Conduits: []alerts.Conduit{}, Violations: maps.Clone(nm.zoneViolations)}
	if nm.zones == nil {
		return out
	}
	counts := map[string]int{}
	for _, mac := range nm.Cache.Keys() {
		if d, ok := nm.Cache.Peek(mac); ok && d.Zone != "" {
			counts[d.Zone]++
		}
	}
	for _, z := range nm.zones.Zones() {
		out.Zones = append(out.Zones, ZoneInfo{Zone: z, Devices: counts[z.ID]})
	}
	out.Conduits = append(out.Conduits, nm.zones.Conduits()...)
	return out
}
