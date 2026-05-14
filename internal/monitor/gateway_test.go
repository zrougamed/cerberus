package monitor

import (
	"net"
	"testing"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/network"
)

func newGatewayTestMonitor(t *testing.T) *NetworkMonitor {
	t.Helper()
	_, lan, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return &NetworkMonitor{
		topology: &network.NetworkTopology{
			LocalSubnets: []*net.IPNet{lan},
		},
	}
}

func TestUpdateDeviceIPLocalSourceUpdates(t *testing.T) {
	nm := newGatewayTestMonitor(t)
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP}

	nm.updateDeviceIP(device, evt, "192.168.1.50")

	if device.IP != "192.168.1.50" {
		t.Fatalf("expected device IP set to LAN source, got %q", device.IP)
	}
	if device.IsGateway {
		t.Fatal("LAN-sourced traffic must not flag device as gateway")
	}
	if device.ForwardedSourceCount != 0 {
		t.Fatalf("forwarded count should stay zero, got %d", device.ForwardedSourceCount)
	}
}

func TestUpdateDeviceIPForwardedExternalDoesNotOverwrite(t *testing.T) {
	nm := newGatewayTestMonitor(t)
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.1"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP}

	nm.updateDeviceIP(device, evt, "8.8.8.8")
	nm.updateDeviceIP(device, evt, "1.1.1.1")

	if device.IP != "192.168.1.1" {
		t.Fatalf("forwarded external src must not overwrite IP, got %q", device.IP)
	}
	if !device.IsGateway {
		t.Fatal("forwarded external traffic should flag device as gateway")
	}
	if device.ForwardedSourceCount != 2 {
		t.Fatalf("expected forwarded count 2, got %d", device.ForwardedSourceCount)
	}
}

func TestUpdateDeviceIPARPAlwaysTrusted(t *testing.T) {
	nm := newGatewayTestMonitor(t)
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01", IP: "0.0.0.0"}
	arpEvt := &models.NetworkEvent{EventType: models.EVENT_TYPE_ARP}

	nm.updateDeviceIP(device, arpEvt, "192.168.1.1")
	if device.IP != "192.168.1.1" {
		t.Fatalf("ARP event should set device IP, got %q", device.IP)
	}

	// ARP must override even when previously poisoned with junk.
	device.IP = "10.0.0.99"
	nm.updateDeviceIP(device, arpEvt, "192.168.1.1")
	if device.IP != "192.168.1.1" {
		t.Fatalf("ARP must reassert real binding, got %q", device.IP)
	}
}

func TestUpdateDeviceIPIgnoresZeroSrc(t *testing.T) {
	nm := newGatewayTestMonitor(t)
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.50"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_UDP}

	nm.updateDeviceIP(device, evt, "0.0.0.0")
	nm.updateDeviceIP(device, evt, "")

	if device.IP != "192.168.1.50" {
		t.Fatalf("zero/empty srcIP must be a no-op, got %q", device.IP)
	}
	if device.IsGateway || device.ForwardedSourceCount != 0 {
		t.Fatalf("zero/empty srcIP must not flag gateway, got is_gw=%v count=%d",
			device.IsGateway, device.ForwardedSourceCount)
	}
}

func TestUpdateDeviceIPNoTopologyFallsBackToPrivate(t *testing.T) {
	nm := &NetworkMonitor{}
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP}

	nm.updateDeviceIP(device, evt, "10.20.30.40")
	if device.IP != "10.20.30.40" {
		t.Fatalf("RFC1918 srcIP should be accepted as device IP without topology, got %q", device.IP)
	}

	device2 := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:02", IP: "10.20.30.1"}
	nm.updateDeviceIP(device2, evt, "8.8.8.8")
	if device2.IP != "10.20.30.1" {
		t.Fatalf("public srcIP should not overwrite device IP, got %q", device2.IP)
	}
	if !device2.IsGateway || device2.ForwardedSourceCount != 1 {
		t.Fatalf("public srcIP should flag gateway, got is_gw=%v count=%d",
			device2.IsGateway, device2.ForwardedSourceCount)
	}
}

func TestUpdateDeviceIPIPv6KeepsFirstSeen(t *testing.T) {
	nm := newGatewayTestMonitor(t)
	device := &models.DeviceInfo{MAC: "aa:bb:cc:dd:ee:01"}
	evt := &models.NetworkEvent{EventType: models.EVENT_TYPE_TCP, IsIPv6: 1}

	nm.updateDeviceIP(device, evt, "fe80::1")
	if device.IP != "fe80::1" {
		t.Fatalf("first IPv6 srcIP should set device IP, got %q", device.IP)
	}

	nm.updateDeviceIP(device, evt, "2001:db8::1234")
	if device.IP != "fe80::1" {
		t.Fatalf("subsequent IPv6 srcIP should not overwrite, got %q", device.IP)
	}
}
