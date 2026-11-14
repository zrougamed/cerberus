package industrial

import (
	"encoding/binary"
	"testing"
)

// bvlc wraps an NPDU+APDU in an Original-Unicast BVLC header.
func bvlc(fn byte, body ...byte) []byte {
	n := 4 + len(body)
	out := make([]byte, 128)
	copy(out, append([]byte{0x81, fn, byte(n >> 8), byte(n)}, body...))
	return out
}

// npdu with no routing information, expecting a reply.
func npdu(apdu ...byte) []byte { return append([]byte{0x01, 0x04}, apdu...) }

func iAm(instance uint32, vendorTag ...byte) []byte {
	oid := make([]byte, 4)
	binary.BigEndian.PutUint32(oid, 8<<22|instance)
	a := append([]byte{0x10, 0x00, 0xC4}, oid...)
	a = append(a, 0x22, 0x05, 0xC4, 0x91, 0x00) // max APDU 1476, segmentation both
	return append(a, vendorTag...)
}

func TestDecodeBACnet_Services(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		frame    []byte
		fn       string
		class    Class
		response bool
		exc      uint8
	}{
		{"read property", bvlc(0x0A, npdu(0x00, 0x05, 0x01, 0x0C, 0x0C, 0x02, 0, 0, 1, 0x19, 0x55)...), "read_property", ClassRead, false, 0},
		{"write property", bvlc(0x0A, npdu(0x00, 0x05, 0x02, 0x0F, 0x0C)...), "write_property", ClassWrite, false, 0},
		{"segmented confirmed request", bvlc(0x0A, npdu(0x08, 0x05, 0x02, 0x00, 0x04, 0x10)...), "write_property_multiple", ClassWrite, false, 0},
		{"device communication control", bvlc(0x0A, npdu(0x00, 0x05, 0x03, 0x11)...), "device_communication_control", ClassControl, false, 0},
		{"reinitialize device", bvlc(0x0A, npdu(0x00, 0x05, 0x03, 0x14)...), "reinitialize_device", ClassControl, false, 0},
		{"unknown confirmed service", bvlc(0x0A, npdu(0x00, 0x05, 0x03, 0x63)...), "service_99", ClassOther, false, 0},
		{"who-is broadcast", bvlc(0x0B, npdu(0x10, 0x08)...), "who_is", ClassOther, false, 0},
		{"write group", bvlc(0x0B, npdu(0x10, 0x0A)...), "write_group", ClassWrite, false, 0},
		{"simple ack", bvlc(0x0A, npdu(0x20, 0x02, 0x0F)...), "write_property", ClassOther, true, 0},
		{"complex ack", bvlc(0x0A, npdu(0x30, 0x01, 0x0C, 0x0C)...), "read_property", ClassOther, true, 0},
		{"segmented complex ack", bvlc(0x0A, npdu(0x38, 0x01, 0x00, 0x04, 0x0E)...), "read_property_multiple", ClassOther, true, 0},
		{"error", bvlc(0x0A, npdu(0x50, 0x02, 0x0F, 0x91, 0x02)...), "write_property", ClassOther, true, 1},
		{"reject", bvlc(0x0A, npdu(0x60, 0x02, 0x04)...), "reject", ClassOther, true, 1},
		{"abort", bvlc(0x0A, npdu(0x70, 0x02, 0x04)...), "abort", ClassOther, true, 1},
		{"segment ack", bvlc(0x0A, npdu(0x40, 0x02, 0x00, 0x04)...), "segment_ack", ClassOther, true, 0},
		{"i-have", bvlc(0x0B, npdu(0x10, 0x01)...), "i_have", ClassOther, true, 0},
		{"network layer message", bvlc(0x0B, 0x01, 0x80, 0x00), "network_message", ClassOther, false, 0},
		{"bdt write", bvlc(0x01), "write_broadcast_distribution_table", ClassWrite, false, 0},
		{"register foreign device", bvlc(0x05, 0x00, 0x3C), "register_foreign_device", ClassOther, false, 0},
		{"forwarded npdu", bvlc(0x04, append([]byte{10, 0, 0, 5, 0xBA, 0xC0}, npdu(0x00, 0x05, 0x01, 0x0F)...)...), "write_property", ClassWrite, false, 0},
		{"distribute broadcast", bvlc(0x09, npdu(0x10, 0x08)...), "who_is", ClassOther, false, 0},
		{"routed to a remote network", bvlc(0x0A, 0x01, 0x24, 0x00, 0x05, 0x01, 0x07, 0xFF, 0x00, 0x05, 0x01, 0x0F), "write_property", ClassWrite, false, 0},
		{"routed from a remote network", bvlc(0x0A, 0x01, 0x08, 0x00, 0x05, 0x01, 0x07, 0x10, 0x08), "who_is", ClassOther, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeBACnet(tt.frame)
			if !ok || m.Protocol != ProtocolBACnet || m.FunctionName != tt.fn || m.Class != tt.class || m.Response != tt.response || m.Exception != tt.exc {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
		})
	}
}

func TestDecodeBACnet_IAm(t *testing.T) {
	t.Parallel()
	m, ok := DecodeBACnet(bvlc(0x0B, npdu(iAm(260001, 0x21, 0x05)...)...))
	if !ok || m.FunctionName != "i_am" || !m.Response || m.Detail != "device 260001" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
	want := Identity{Vendor: "BACnet vendor 5", Model: "device 260001", DeviceType: "BACnet device"}
	if m.Identity == nil || *m.Identity != want {
		t.Fatalf("identity = %+v", m.Identity)
	}
	m, _ = DecodeBACnet(bvlc(0x0B, npdu(iAm(7, 0x22, 0x01, 0x04)...)...))
	if m.Identity.Vendor != "BACnet vendor 260" {
		t.Fatalf("2-byte vendor = %+v", m.Identity)
	}
}

func TestParseIAm_Partial(t *testing.T) {
	t.Parallel()
	full := iAm(42, 0x21, 0x05)[2:] // drop APDU type and service
	tests := map[string]struct {
		b        []byte
		identity bool
		vendor   string
	}{
		"empty":                 {nil, false, ""},
		"no object id tag":      {[]byte{0x21, 1, 2, 3, 4}, false, ""},
		"stops after object id": {full[:5], true, ""},
		"max apdu cut":          {full[:6], true, ""},
		"vendor tag missing":    {full[:10], true, ""},
		"vendor wrong tag":      {append(append([]byte(nil), full[:10]...), 0x91, 0x01), true, ""},
		"vendor length 3":       {append(append([]byte(nil), full[:10]...), 0x23, 0, 0, 1), true, ""},
		"vendor value cut":      {append(append([]byte(nil), full[:10]...), 0x22, 0x01), true, ""},
		"complete":              {full, true, "BACnet vendor 5"},
	}
	for name, tt := range tests {
		id, _ := parseIAm(tt.b)
		if (id != nil) != tt.identity || (id != nil && id.Vendor != tt.vendor) {
			t.Errorf("%s: identity = %+v", name, id)
		}
	}
}

func TestDecodeBACnet_Rejects(t *testing.T) {
	t.Parallel()
	shortLen := bvlc(0x0A, npdu(0x10, 0x08)...)
	shortLen[3] = 3
	tests := map[string][]byte{
		"empty":                  nil,
		"zero padded":            make([]byte, 128),
		"wrong bvlc type":        {0x82, 0x0A, 0, 8, 1, 4, 0x10, 8},
		"bvlc length below 4":    shortLen,
		"unknown bvlc function":  bvlc(0x0D, 0x00),
		"forwarded too short":    bvlc(0x04, 1, 2),
		"npdu wrong version":     bvlc(0x0A, 0x02, 0x04, 0x10, 0x08),
		"npdu cut":               bvlc(0x0A, 0x01),
		"dest spec cut":          bvlc(0x0A, 0x01, 0x20, 0x00),
		"dest address cut":       bvlc(0x0A, 0x01, 0x20, 0x00, 0x05, 0x06, 1),
		"src spec cut":           bvlc(0x0A, 0x01, 0x08, 0x00),
		"src address cut":        bvlc(0x0A, 0x01, 0x08, 0x00, 0x05, 0x06, 1),
		"hop count missing":      bvlc(0x0A, 0x01, 0x20, 0x00, 0x05, 0x00),
		"no apdu":                bvlc(0x0A, 0x01, 0x04),
		"apdu type out of range": bvlc(0x0A, npdu(0x90, 0x00)...),
		"confirmed service cut":  bvlc(0x0A, npdu(0x00, 0x05, 0x01)...),
		"modbus on bacnet port":  mbap(1, 0x03, 0, 0, 0, 1),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeBACnet(frame); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
}

func FuzzDecodeBACnet(f *testing.F) {
	f.Add(bvlc(0x0B, npdu(iAm(1, 0x21, 5)...)...))
	f.Add(bvlc(0x0A, npdu(0x00, 0x05, 0x01, 0x0F)...))
	f.Add(bvlc(0x04, append([]byte{10, 0, 0, 5, 0xBA, 0xC0}, npdu(0x30, 1, 0x0C)...)...))
	f.Fuzz(func(t *testing.T, p []byte) {
		if m, ok := DecodeBACnet(p); ok && (m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
