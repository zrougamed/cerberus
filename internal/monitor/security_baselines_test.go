package monitor

import (
	"strings"
	"testing"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

func defaultBaselines() alerts.BaselineConfig {
	return alerts.DefaultConfig().Baselines
}

func newTestMonitor(cfg alerts.BaselineConfig) *NetworkMonitor {
	nm := &NetworkMonitor{
		alerts:         make([]models.AlertEvent, 0),
		alertRuleState: make(map[string]bool),
		alertConfig:    alerts.DefaultConfig(),
	}
	nm.baselines = newSecurityBaselines(cfg)
	return nm
}

func dhcpReplyPayload() [models.L7PayloadSize]byte {
	var p [models.L7PayloadSize]byte
	p[0] = 2 // BOOTREPLY
	return p
}

func TestRogueDHCPLearningMode(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())

	first := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	rogue := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}

	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}

	nm.baselines.checkDHCP(nm, first, evt, "192.168.1.1")
	if len(nm.alerts) != 0 {
		t.Fatalf("expected no alerts after first DHCP server, got %d", len(nm.alerts))
	}

	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.99")
	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "rogue_dhcp_server" {
		t.Fatalf("expected rogue_dhcp_server alert, got %+v", nm.alerts)
	}
	if !strings.Contains(nm.alerts[0].Message, "192.168.1.99") {
		t.Fatalf("alert message missing rogue IP: %q", nm.alerts[0].Message)
	}
}

func TestRogueDHCPStrictMode(t *testing.T) {
	cfg := defaultBaselines()
	cfg.RogueDHCPServer.KnownGood = []string{"192.168.1.1"}
	nm := newTestMonitor(cfg)

	good := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	rogue := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}

	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}

	nm.baselines.checkDHCP(nm, good, evt, "192.168.1.1")
	if len(nm.alerts) != 0 {
		t.Fatalf("expected no alerts for known-good server, got %d", len(nm.alerts))
	}

	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.2")
	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "rogue_dhcp_server" {
		t.Fatalf("expected rogue_dhcp_server alert in strict mode, got %+v", nm.alerts)
	}
}

func TestRogueDHCPDisabled(t *testing.T) {
	cfg := defaultBaselines()
	cfg.RogueDHCPServer.Enabled = false
	nm := newTestMonitor(cfg)

	first := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	rogue := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}

	nm.baselines.checkDHCP(nm, first, evt, "192.168.1.1")
	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.99")
	if len(nm.alerts) != 0 {
		t.Fatalf("disabled rogue_dhcp_server must not alert, got %+v", nm.alerts)
	}
}

func TestDHCPClientRequestIgnored(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())

	device := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	var clientReq [models.L7PayloadSize]byte
	clientReq[0] = 1 // BOOTREQUEST

	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: clientReq}
	nm.baselines.checkDHCP(nm, device, evt, "0.0.0.0")
	nm.baselines.checkDHCP(nm, device, evt, "192.168.1.50")

	if len(nm.alerts) != 0 {
		t.Fatalf("client requests must not seed baseline or alert, got %d alerts", len(nm.alerts))
	}
	if len(nm.baselines.dhcpServers) != 0 {
		t.Fatalf("client requests must not populate dhcpServers, got %d entries", len(nm.baselines.dhcpServers))
	}
}

func TestRogueIPv6RouterAdvertisement(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())

	router := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	rogue := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}

	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ICMP,
		Protocol:  protoICMPv6,
		ICMPType:  icmpv6TypeRouterAdvert,
		IsIPv6:    1,
	}

	nm.baselines.checkRA(nm, router, evt, "fe80::1")
	if len(nm.alerts) != 0 {
		t.Fatalf("first RA must not alert, got %d", len(nm.alerts))
	}

	nm.baselines.checkRA(nm, rogue, evt, "fe80::dead")
	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "rogue_ipv6_ra_source" {
		t.Fatalf("expected rogue_ipv6_ra_source alert, got %+v", nm.alerts)
	}
}

func TestRouterAdvertNonType134Ignored(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())
	device := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}

	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ICMP,
		Protocol:  protoICMPv6,
		ICMPType:  135, // Neighbor Solicitation
		IsIPv6:    1,
	}
	nm.baselines.checkRA(nm, device, evt, "fe80::abc")
	if len(nm.alerts) != 0 || len(nm.baselines.raSources) != 0 {
		t.Fatalf("non-RA ICMPv6 must be ignored, got %d alerts %d baselines",
			len(nm.alerts), len(nm.baselines.raSources))
	}
}

func TestGatewayMACChanged(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())

	server := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	dhcpEvt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}
	nm.baselines.checkDHCP(nm, server, dhcpEvt, "192.168.1.1")

	// Same MAC in ARP reply: no alert.
	matchingARP := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ARP,
		ArpOp:     2,
		ArpSha:    [6]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01},
	}
	nm.baselines.checkARP(nm, server, matchingARP, "192.168.1.1")
	if len(nm.alerts) != 0 {
		t.Fatalf("matching MAC must not alert, got %d", len(nm.alerts))
	}

	// Different MAC claiming the same gateway IP: alert.
	spoofer := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}
	spoofARP := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ARP,
		ArpOp:     2,
		ArpSha:    [6]byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x02},
	}
	nm.baselines.checkARP(nm, spoofer, spoofARP, "192.168.1.1")
	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "gateway_mac_changed" {
		t.Fatalf("expected gateway_mac_changed alert, got %+v", nm.alerts)
	}
}

func TestGatewayMACChangedIgnoresUnknownIP(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())
	device := &models.DeviceInfo{MAC: "cc:cc:cc:cc:cc:03"}

	evt := &models.NetworkEvent{
		EventType: models.EVENT_TYPE_ARP,
		ArpOp:     2,
		ArpSha:    [6]byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x03},
	}
	nm.baselines.checkARP(nm, device, evt, "192.168.1.50")
	if len(nm.alerts) != 0 {
		t.Fatalf("ARP for non-server IP must not alert, got %d", len(nm.alerts))
	}
}

func TestDHCPServerMACChangeFiresGatewayAlert(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())

	original := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	imposter := &models.DeviceInfo{MAC: "cc:cc:cc:cc:cc:03"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}

	nm.baselines.checkDHCP(nm, original, evt, "192.168.1.1")
	if len(nm.alerts) != 0 {
		t.Fatalf("expected no alerts after first DHCP server, got %d", len(nm.alerts))
	}

	// Second reply from same server IP but a different MAC must alert, not
	// silently rebind the baseline.
	nm.baselines.checkDHCP(nm, imposter, evt, "192.168.1.1")
	if len(nm.alerts) != 1 || nm.alerts[0].Rule != "gateway_mac_changed" {
		t.Fatalf("expected gateway_mac_changed alert on DHCP MAC change, got %+v", nm.alerts)
	}
	if nm.baselines.serverMACs["192.168.1.1"] != "aa:aa:aa:aa:aa:01" {
		t.Fatalf("baseline MAC must not be overwritten, got %q",
			nm.baselines.serverMACs["192.168.1.1"])
	}
}

func TestRogueDHCPDedup(t *testing.T) {
	nm := newTestMonitor(defaultBaselines())
	good := &models.DeviceInfo{MAC: "aa:aa:aa:aa:aa:01"}
	rogue := &models.DeviceInfo{MAC: "bb:bb:bb:bb:bb:02"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP, L7Payload: dhcpReplyPayload()}

	nm.baselines.checkDHCP(nm, good, evt, "192.168.1.1")
	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.99")
	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.99")
	nm.baselines.checkDHCP(nm, rogue, evt, "192.168.1.99")

	if len(nm.alerts) != 1 {
		t.Fatalf("rogue server must alert once, got %d", len(nm.alerts))
	}
}
