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
	// maxIndustrialDetails bounds IndustrialStats.Details (e.g. distinct
	// rack/slot pairs); a device rarely has more than a few.
	maxIndustrialDetails = 16
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

// industrialRuleTarget is what a rule alerts on: requests of one class, or
// requests carrying one flag.
type industrialRuleTarget struct {
	protocol string
	class    industrial.Class
	flag     string
}

func (t industrialRuleTarget) key() string {
	if t.flag != "" {
		return t.protocol + "|flag:" + t.flag
	}
	return t.protocol + "|" + string(t.class)
}

var industrialRuleTargets = map[string]industrialRuleTarget{
	alerts.RuleModbusWrite:      {protocol: industrial.ProtocolModbus, class: industrial.ClassWrite},
	alerts.RuleModbusDiagnostic: {protocol: industrial.ProtocolModbus, class: industrial.ClassDiagnostic},
	alerts.RuleS7Write:          {protocol: industrial.ProtocolS7, class: industrial.ClassWrite},
	alerts.RuleS7Control:        {protocol: industrial.ProtocolS7, class: industrial.ClassControl},
	alerts.RuleS7Program:        {protocol: industrial.ProtocolS7, class: industrial.ClassProgram},
	alerts.RuleDNP3Control:      {protocol: industrial.ProtocolDNP3, class: industrial.ClassControl},
	alerts.RuleDNP3Diagnostic:   {protocol: industrial.ProtocolDNP3, class: industrial.ClassDiagnostic},
	alerts.RuleENIPWrite:        {protocol: industrial.ProtocolENIP, class: industrial.ClassWrite},
	alerts.RuleENIPControl:      {protocol: industrial.ProtocolENIP, class: industrial.ClassControl},
	alerts.RuleBACnetWrite:      {protocol: industrial.ProtocolBACnet, class: industrial.ClassWrite},
	alerts.RuleBACnetControl:    {protocol: industrial.ProtocolBACnet, class: industrial.ClassControl},
	alerts.RuleIEC104Control:    {protocol: industrial.ProtocolIEC104, class: industrial.ClassControl},
	alerts.RuleIEC104Diagnostic: {protocol: industrial.ProtocolIEC104, class: industrial.ClassDiagnostic},
	alerts.RuleOPCUAWrite:       {protocol: industrial.ProtocolOPCUA, class: industrial.ClassWrite},
	alerts.RuleOPCUAInsecure:    {protocol: industrial.ProtocolOPCUA, flag: industrial.FlagInsecurePolicy},
	alerts.RuleMQTTAnonymous:    {protocol: industrial.ProtocolMQTT, flag: industrial.FlagNoUsername},
}

// newIndustrialRules maps each target key to the enabled rule for it.
func newIndustrialRules(cfg alerts.IndustrialConfig) map[string]*industrialRule {
	rules := make(map[string]*industrialRule)
	for _, r := range cfg.Rules() {
		target, ok := industrialRuleTargets[r.ID]
		if !ok || !r.Rule.Enabled {
			continue
		}
		rules[target.key()] = &industrialRule{id: r.ID, cfg: *r.Rule, allow: r.Rule.SourcePrefixes()}
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
	if msg.Identity != nil && msg.Response {
		recordAsset(device, msg.Protocol, msg.Identity, now)
	}
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
	if msg.Detail != "" {
		if s.Details == nil {
			s.Details = make(map[string]int)
		}
		if _, seen := s.Details[msg.Detail]; seen || len(s.Details) < maxIndustrialDetails {
			s.Details[msg.Detail]++
		}
	}
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

// recordAsset stores the identity a device announced about itself.
func recordAsset(device *models.DeviceInfo, protocol string, id *industrial.Identity, now time.Time) {
	device.Asset = &models.AssetInfo{
		Vendor:     id.Vendor,
		Model:      id.Model,
		Firmware:   id.Firmware,
		Serial:     id.Serial,
		DeviceType: id.DeviceType,
		Source:     protocol,
		UpdatedAt:  now,
	}
}

func (nm *NetworkMonitor) checkIndustrialAlert(device *models.DeviceInfo, msg industrial.Message, srcIP, dstIP string, now time.Time) {
	keys := []string{industrialRuleTarget{protocol: msg.Protocol, class: msg.Class}.key()}
	if msg.Flag != "" {
		keys = append(keys, industrialRuleTarget{protocol: msg.Protocol, flag: msg.Flag}.key())
	}
	for _, k := range keys {
		if rule := nm.industrialRules[k]; rule != nil && !rule.allows(srcIP) {
			nm.raiseIndustrialAlert(rule, device, msg, srcIP, dstIP, now)
		}
	}
}

func (nm *NetworkMonitor) raiseIndustrialAlert(rule *industrialRule, device *models.DeviceInfo, msg industrial.Message, srcIP, dstIP string, now time.Time) {
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
	industrial.ProtocolS7:     "S7comm",
	industrial.ProtocolS7Plus: "S7comm-plus",
	industrial.ProtocolDNP3:   "DNP3",
	industrial.ProtocolENIP:   "EtherNet/IP",
	industrial.ProtocolBACnet: "BACnet",
	industrial.ProtocolIEC104: "IEC 104",
	industrial.ProtocolOPCUA:  "OPC UA",
	industrial.ProtocolMQTT:   "MQTT",
}

var flagLabels = map[string]string{
	industrial.FlagInsecurePolicy: "no message security",
	industrial.FlagNoUsername:     "no username",
}

func industrialAlertMessage(msg industrial.Message, srcIP, dstIP string) string {
	text := fmt.Sprintf("%s %s from %s to %s", protocolLabels[msg.Protocol], msg.FunctionName, srcIP, dstIP)
	if msg.HasUnit {
		text += fmt.Sprintf(" unit %d", msg.Unit)
	}
	if msg.HasRange {
		text += fmt.Sprintf(", address %d count %d", msg.Address, msg.Quantity)
	}
	if msg.Detail != "" {
		text += " (" + msg.Detail + ")"
	}
	if label := flagLabels[msg.Flag]; label != "" {
		text += ", " + label
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
		c.Details = cloneStringIntMap(s.Details)
		out[proto] = &c
	}
	return out
}
