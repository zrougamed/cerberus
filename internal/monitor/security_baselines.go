package monitor

import (
	"fmt"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/utils"
)

const (
	protoICMPv6            uint8 = 58
	icmpv6TypeRouterAdvert uint8 = 134
)

// securityBaselines tracks first-seen-wins fingerprints for network infrastructure
// and fires alerts when later observations contradict the baseline. Covers rogue
// DHCP servers, rogue IPv6 Router Advertisement sources, and ARP-spoof attempts
// against DHCP-server IPs.
//
// Two modes per protocol:
//   - strict: baseline seeded from BaselineRule.KnownGood; anything else alerts.
//   - learning: empty baseline at startup; the first observed source wins and any
//     subsequent newcomer alerts.
type securityBaselines struct {
	dhcpServers    map[string]bool   // server IPv4 -> known good
	raSources      map[string]bool   // router source IPv6 -> known good
	serverMACs     map[string]string // DHCP-server IPv4 -> MAC observed when it last replied
	dhcpStrict     bool
	raStrict       bool
	dhcpEnabled    bool
	raEnabled      bool
	gatewayEnabled bool
}

func newSecurityBaselines(cfg alerts.BaselineConfig) *securityBaselines {
	b := &securityBaselines{
		dhcpServers:    make(map[string]bool),
		raSources:      make(map[string]bool),
		serverMACs:     make(map[string]string),
		dhcpStrict:     len(cfg.RogueDHCPServer.KnownGood) > 0,
		raStrict:       len(cfg.RogueIPv6RASource.KnownGood) > 0,
		dhcpEnabled:    cfg.RogueDHCPServer.Enabled,
		raEnabled:      cfg.RogueIPv6RASource.Enabled,
		gatewayEnabled: cfg.GatewayMACChanged.Enabled,
	}
	for _, ip := range cfg.RogueDHCPServer.KnownGood {
		b.dhcpServers[ip] = true
	}
	for _, ip := range cfg.RogueIPv6RASource.KnownGood {
		b.raSources[ip] = true
	}
	return b
}

// checkDHCP inspects UDP traffic already classified as DHCP. A BOOTREPLY (op=2)
// identifies the sender as a DHCP server. Also records the server IP -> MAC
// binding so subsequent ARP replies for that IP can be checked for spoofing.
// The MAC binding is seeded once on first observation; a later DHCP reply from
// the same IP with a different MAC fires gateway_mac_changed rather than
// silently overwriting the baseline.
func (b *securityBaselines) checkDHCP(nm *NetworkMonitor, device *models.DeviceInfo, evt *models.NetworkEvent, srcIP string) {
	if !b.dhcpEnabled && !b.gatewayEnabled {
		return
	}
	if !utils.IsDHCPServerReply(evt.L7Payload) {
		return
	}
	if srcIP == "" || srcIP == "0.0.0.0" {
		return
	}
	if b.dhcpServers[srcIP] {
		b.recordServerMAC(nm, device, srcIP)
		return
	}
	if !b.dhcpStrict && len(b.dhcpServers) == 0 {
		b.dhcpServers[srcIP] = true
		b.serverMACs[srcIP] = device.MAC
		return
	}
	if b.dhcpEnabled {
		nm.fireAlertIfNeeded(device, "rogue_dhcp_server", true, "high",
			fmt.Sprintf("Rogue DHCP server reply from %s (%s)", srcIP, device.MAC))
	}
}

// recordServerMAC seeds the server IP -> MAC binding on first observation. If a
// binding already exists and the new MAC differs, fires gateway_mac_changed
// instead of overwriting, so a spoofer cannot poison the ARP-spoof baseline by
// simply sending one DHCP reply from the legitimate server's IP.
func (b *securityBaselines) recordServerMAC(nm *NetworkMonitor, device *models.DeviceInfo, srcIP string) {
	existing, ok := b.serverMACs[srcIP]
	if !ok {
		b.serverMACs[srcIP] = device.MAC
		return
	}
	if existing == device.MAC {
		return
	}
	if !b.gatewayEnabled {
		return
	}
	nm.fireAlertIfNeeded(device, "gateway_mac_changed", true, "high",
		fmt.Sprintf("DHCP server %s MAC changed from %s to %s", srcIP, existing, device.MAC))
}

// checkRA inspects ICMPv6 events for Router Advertisement (type 134). First-seen
// source becomes baseline unless strict mode is in effect.
func (b *securityBaselines) checkRA(nm *NetworkMonitor, device *models.DeviceInfo, evt *models.NetworkEvent, srcIP string) {
	if !b.raEnabled {
		return
	}
	if evt.Protocol != protoICMPv6 || evt.ICMPType != icmpv6TypeRouterAdvert {
		return
	}
	if srcIP == "" {
		return
	}
	if b.raSources[srcIP] {
		return
	}
	if !b.raStrict && len(b.raSources) == 0 {
		b.raSources[srcIP] = true
		return
	}
	nm.fireAlertIfNeeded(device, "rogue_ipv6_ra_source", true, "high",
		fmt.Sprintf("Rogue IPv6 Router Advertisement from %s (%s)", srcIP, device.MAC))
}

// checkARP fires gateway_mac_changed when an ARP reply claims a DHCP-server IP
// with a MAC different from the one previously recorded for that server. The
// ARP body's sender hardware address (arp_sha) is used rather than the Ethernet
// source MAC, since a spoofer may set those independently.
func (b *securityBaselines) checkARP(nm *NetworkMonitor, device *models.DeviceInfo, evt *models.NetworkEvent, srcIP string) {
	if !b.gatewayEnabled {
		return
	}
	if evt.EventType != models.EVENT_TYPE_ARP || evt.ArpOp != 2 {
		return
	}
	expected, known := b.serverMACs[srcIP]
	if !known {
		return
	}
	observed := utils.MacToString(evt.ArpSha)
	if observed == "" || observed == "00:00:00:00:00:00" {
		return
	}
	if observed == expected {
		return
	}
	nm.fireAlertIfNeeded(device, "gateway_mac_changed", true, "high",
		fmt.Sprintf("DHCP server %s MAC changed from %s to %s", srcIP, expected, observed))
}
