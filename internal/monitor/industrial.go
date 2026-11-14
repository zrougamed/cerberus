package monitor

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"
)

const (
	// maxIndustrialPeers bounds IndustrialStats.Peers. A PLC usually has a
	// handful of clients; a SCADA server polling hundreds of PLCs keeps the
	// most recent ones.
	maxIndustrialPeers = 32
	// maxIndustrialAlertKeys bounds the re-alert state, same policy as the
	// watchlists.
	maxIndustrialAlertKeys = 4096
)

// IndustrialCountKey identifies one series of cerberus_industrial_messages_total.
type IndustrialCountKey struct {
	Protocol string
	Class    string
	Response bool
}

// industrialRule is an alerts.IndustrialRule with its allow-list parsed.
type industrialRule struct {
	id    string
	cfg   alerts.IndustrialRule
	allow []netip.Prefix
}

func (r *industrialRule) allows(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range r.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// newIndustrialRules maps "<protocol>|<class>" to the enabled rule that
// alerts on it.
func newIndustrialRules(cfg alerts.IndustrialConfig) map[string]*industrialRule {
	defs := []struct {
		protocol string
		class    industrial.Class
		id       string
		rule     alerts.IndustrialRule
	}{
		{industrial.ProtocolModbus, industrial.ClassWrite, alerts.RuleModbusWrite, cfg.ModbusWrite},
		{industrial.ProtocolModbus, industrial.ClassDiagnostic, alerts.RuleModbusDiagnostic, cfg.ModbusDiagnostic},
	}
	rules := make(map[string]*industrialRule, len(defs))
	for _, d := range defs {
		if !d.rule.Enabled {
			continue
		}
		rules[d.protocol+"|"+string(d.class)] = &industrialRule{id: d.id, cfg: d.rule, allow: d.rule.SourcePrefixes()}
	}
	return rules
}

// trackIndustrial runs the industrial decoders on TCP/UDP payloads, updates
// the device counters and raises alerts for risky requests. Caller holds
// nm.mu.
func (nm *NetworkMonitor) trackIndustrial(device *models.DeviceInfo, evt *models.NetworkEvent, srcIP, dstIP string, now time.Time) {
	if evt.EventType != models.EVENT_TYPE_TCP && evt.EventType != models.EVENT_TYPE_UDP {
		return
	}
	msg, ok := industrial.Decode(evt.Protocol, evt.SrcPort, evt.DstPort, evt.L7Payload[:])
	if !ok {
		return
	}
	recordIndustrial(device, msg, dstIP, now)
	nm.industrialCounts[IndustrialCountKey{Protocol: msg.Protocol, Class: string(msg.Class), Response: msg.Response}]++
	if !msg.Response {
		nm.checkIndustrialAlert(device, msg, srcIP, dstIP, now)
	}
}

func recordIndustrial(device *models.DeviceInfo, msg industrial.Message, peer string, now time.Time) {
	if device.Industrial == nil {
		device.Industrial = make(map[string]*models.IndustrialStats)
	}
	s := device.Industrial[msg.Protocol]
	if s == nil {
		s = &models.IndustrialStats{}
		device.Industrial[msg.Protocol] = s
	}
	// Records loaded from older JSON may lack the maps.
	if s.Operations == nil {
		s.Operations = make(map[string]int)
	}
	if s.Functions == nil {
		s.Functions = make(map[string]int)
	}
	s.LastSeen = now
	if msg.Response {
		s.Responses++
		if msg.Exception != 0 {
			s.Exceptions++
		}
	} else {
		s.Requests++
		s.Operations[string(msg.Class)]++
		s.Functions[msg.FunctionName]++
	}
	if peer == "" || peer == "0.0.0.0" {
		return
	}
	if i := slices.Index(s.Peers, peer); i >= 0 {
		s.Peers = append(s.Peers[:i], s.Peers[i+1:]...)
	}
	s.Peers = append(s.Peers, peer)
	if len(s.Peers) > maxIndustrialPeers {
		s.Peers = s.Peers[len(s.Peers)-maxIndustrialPeers:]
	}
}

func (nm *NetworkMonitor) checkIndustrialAlert(device *models.DeviceInfo, msg industrial.Message, srcIP, dstIP string, now time.Time) {
	rule := nm.industrialRules[msg.Protocol+"|"+string(msg.Class)]
	if rule == nil || rule.allows(srcIP) {
		return
	}
	key := fmt.Sprintf("%s|%s|%s|%d", device.MAC, rule.id, dstIP, msg.Unit)
	gap := time.Duration(rule.cfg.RealertSeconds) * time.Second
	if last, ok := nm.industrialLast[key]; ok && now.Sub(last) < gap {
		return
	}
	nm.pruneIndustrialState(now)
	nm.industrialLast[key] = now

	nm.appendAlert(models.AlertEvent{
		ID:         fmt.Sprintf("%d-%s-%s", now.UnixNano(), device.MAC, rule.id),
		DeviceMAC:  device.MAC,
		DeviceIP:   device.IP,
		Vendor:     device.Vendor,
		Rule:       rule.id,
		Severity:   rule.cfg.Severity,
		Message:    industrialAlertMessage(msg, srcIP, dstIP),
		ObservedAt: now,
	})
}

var protocolLabels = map[string]string{
	industrial.ProtocolModbus: "Modbus",
}

func industrialAlertMessage(msg industrial.Message, srcIP, dstIP string) string {
	text := fmt.Sprintf("%s %s from %s to %s unit %d", protocolLabels[msg.Protocol], msg.FunctionName, srcIP, dstIP, msg.Unit)
	if msg.HasRange {
		text += fmt.Sprintf(", address %d count %d", msg.Address, msg.Quantity)
	}
	return text
}

func (nm *NetworkMonitor) pruneIndustrialState(now time.Time) {
	if len(nm.industrialLast) < maxIndustrialAlertKeys {
		return
	}
	var longest time.Duration
	for _, r := range nm.industrialRules {
		longest = max(longest, time.Duration(r.cfg.RealertSeconds)*time.Second)
	}
	for k, t := range nm.industrialLast {
		if now.Sub(t) >= longest {
			delete(nm.industrialLast, k)
		}
	}
	if len(nm.industrialLast) >= maxIndustrialAlertKeys {
		clear(nm.industrialLast)
	}
}

// GetIndustrialCounts returns decoded industrial messages since start.
func (nm *NetworkMonitor) GetIndustrialCounts() map[IndustrialCountKey]uint64 {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return maps.Clone(nm.industrialCounts)
}

func cloneIndustrial(in map[string]*models.IndustrialStats) map[string]*models.IndustrialStats {
	if in == nil {
		return nil
	}
	out := make(map[string]*models.IndustrialStats, len(in))
	for proto, s := range in {
		c := *s
		c.Operations = cloneStringIntMap(s.Operations)
		c.Functions = cloneStringIntMap(s.Functions)
		c.Peers = append([]string(nil), s.Peers...)
		out[proto] = &c
	}
	return out
}
