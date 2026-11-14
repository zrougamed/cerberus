package industrial

import (
	"encoding/binary"
	"strings"
	"testing"
)

func enipFrame(cmd uint16, status uint32, body ...byte) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:2], cmd)
	binary.LittleEndian.PutUint16(h[2:4], uint16(len(body)))
	binary.LittleEndian.PutUint32(h[4:8], 0x12345678)
	binary.LittleEndian.PutUint32(h[8:12], status)
	out := make([]byte, 128)
	copy(out, append(h, body...))
	return out
}

// rrData wraps a CIP message in SendRRData CPF: null address + unconnected data.
func rrData(cip ...byte) []byte {
	b := []byte{0, 0, 0, 0, 0x0A, 0x00, 2, 0, 0, 0, 0, 0, 0xB2, 0, byte(len(cip)), 0}
	return enipFrame(enipSendRRData, 0, append(b, cip...)...)
}

// unitData wraps a CIP message in SendUnitData CPF: connected address + data.
func unitData(cip ...byte) []byte {
	data := append([]byte{0x01, 0x00}, cip...) // sequence count
	b := []byte{0, 0, 0, 0, 0, 0, 2, 0, 0xA1, 0, 4, 0, 1, 2, 3, 4, 0xB1, 0, byte(len(data)), 0}
	return enipFrame(enipSendUnitData, 0, append(b, data...)...)
}

func TestDecodeENIP_CIPRequests(t *testing.T) {
	t.Parallel()
	// Write_Tag "Pump" via Unconnected Send to the Connection Manager.
	writeTag := []byte{0x4D, 0x03, 0x91, 0x04, 'P', 'u', 'm', 'p', 0xC4, 0x00, 1, 0, 0, 0, 0, 0}
	unconn := append([]byte{0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0x0E, byte(len(writeTag)), 0}, writeTag...)
	tests := []struct {
		name  string
		frame []byte
		fn    string
		class Class
	}{
		{"get attribute single on identity", rrData(0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07), "get_attribute_single", ClassRead},
		{"set attribute single", rrData(0x10, 0x03, 0x20, 0x04, 0x24, 0x65, 0x30, 0x03, 1), "set_attribute_single", ClassWrite},
		{"reset identity", rrData(0x05, 0x02, 0x20, 0x01, 0x24, 0x01), "reset", ClassControl},
		{"16-bit class path", rrData(0x01, 0x03, 0x21, 0x00, 0x01, 0x00, 0x25, 0x00, 0x01, 0x00), "get_attributes_all", ClassRead},
		{"16-bit instance then class", rrData(0x01, 0x04, 0x25, 0x00, 0x01, 0x00, 0x20, 0x01, 0x30, 0x01), "get_attributes_all", ClassRead},
		{"forward open", rrData(0x54, 0x02, 0x20, 0x06, 0x24, 0x01), "forward_open", ClassOther},
		{"read tag symbolic", rrData(0x4C, 0x03, 0x91, 0x04, 'P', 'u', 'm', 'p', 1, 0), "read_tag", ClassRead},
		{"write tag through unconnected send", rrData(unconn...), "write_tag", ClassWrite},
		{"connected write tag", unitData(writeTag...), "write_tag", ClassWrite},
		{"unknown class specific", rrData(0x60, 0x02, 0x20, 0x99, 0x24, 0x01), "service_0x60", ClassOther},
		{"unconnected send without embedded request", rrData(0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A), "unconnected_send", ClassOther},
		{"path longer than capture", rrData(0x0E, 0x30, 0x20), "send_rr_data", ClassOther},
		{"truncated 16-bit class", rrData(0x0E, 0x01, 0x21, 0x00), "get_attribute_single", ClassRead},
		{"truncated 16-bit instance", rrData(0x0E, 0x01, 0x25, 0x00), "get_attribute_single", ClassRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeENIP(tt.frame, false)
			if !ok || m.Protocol != ProtocolENIP || m.FunctionName != tt.fn || m.Class != tt.class || m.Response {
				t.Fatalf("got %+v ok=%v, want %s/%s", m, ok, tt.fn, tt.class)
			}
		})
	}
}

func TestDecodeENIP_CIPResponses(t *testing.T) {
	t.Parallel()
	m, ok := DecodeENIP(rrData(0xCD, 0x00, 0x00, 0x00), true)
	if !ok || !m.Response || m.FunctionName != "write_tag" || m.Exception != 0 {
		t.Fatalf("write tag reply: %+v ok=%v", m, ok)
	}
	m, ok = DecodeENIP(rrData(0x8E, 0x00, 0x05, 0x00), true)
	if !ok || m.FunctionName != "get_attribute_single" || m.Exception != 5 {
		t.Fatalf("error reply: %+v ok=%v", m, ok)
	}
	// Reply to a service with no name keeps the encapsulation command.
	m, ok = DecodeENIP(rrData(0xE0, 0x00, 0x00, 0x00), true)
	if !ok || m.FunctionName != "send_rr_data" {
		t.Fatalf("unnamed reply: %+v ok=%v", m, ok)
	}
	// Encapsulation status set on a reply.
	m, ok = DecodeENIP(enipFrame(enipRegister, 0x69), true)
	if !ok || m.Exception != 0x69 || m.FunctionName != "register_session" {
		t.Fatalf("status reply: %+v ok=%v", m, ok)
	}
	m, ok = DecodeENIP(enipFrame(enipRegister, 0x10000), true)
	if !ok || m.Exception != 0xFF {
		t.Fatalf("large status: %+v ok=%v", m, ok)
	}
}

func listIdentityReply(name string) []byte {
	d := make([]byte, 33)
	binary.LittleEndian.PutUint16(d[0:2], 1)         // encapsulation version
	binary.LittleEndian.PutUint16(d[lidVendor:], 1)  // Rockwell
	binary.LittleEndian.PutUint16(d[lidType:], 0x0E) // PLC
	binary.LittleEndian.PutUint16(d[22:24], 0x0037)  // product code
	d[lidRevision], d[lidRevision+1] = 32, 11        // v32.011
	binary.LittleEndian.PutUint32(d[lidSerial:], 0xC0FFEE01)
	d[lidName] = byte(len(name))
	d = append(d, name...)
	d = append(d, 3) // state
	item := []byte{1, 0, 0x0C, 0, byte(len(d)), 0}
	return enipFrame(enipListIdentity, 0, append(item, d...)...)
}

func TestDecodeENIP_ListIdentity(t *testing.T) {
	t.Parallel()
	m, ok := DecodeENIP(listIdentityReply("1756-L83E/B"), true)
	if !ok || m.FunctionName != "list_identity" || m.Identity == nil {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
	want := Identity{Vendor: "Rockwell Automation", Model: "1756-L83E/B", Firmware: "32.011", Serial: "c0ffee01", DeviceType: "programmable logic controller"}
	if *m.Identity != want {
		t.Fatalf("identity = %+v, want %+v", *m.Identity, want)
	}

	// Request (no body) has no identity.
	if m, ok := DecodeENIP(enipFrame(enipListIdentity, 0), false); !ok || m.Identity != nil {
		t.Fatalf("request: %+v ok=%v", m, ok)
	}
}

func TestParseListIdentity_EdgeCases(t *testing.T) {
	t.Parallel()
	// Unknown vendor and type, control characters in the name.
	f := listIdentityReply("PLC\x00\x1b[31m-1")
	f[24+6+lidVendor] = 99
	f[24+6+lidType] = 0x55
	m, _ := DecodeENIP(f, true)
	if m.Identity.Vendor != "CIP vendor 99" || m.Identity.DeviceType != "CIP device type 85" || m.Identity.Model != "PLC[31m-1" {
		t.Fatalf("identity = %+v", m.Identity)
	}
	// Name length past the item: what is there is used.
	long := listIdentityReply(strings.Repeat("A", 70))
	if m, _ := DecodeENIP(long, true); m.Identity == nil || len(m.Identity.Model) == 0 || len(m.Identity.Model) > maxWireString {
		t.Fatalf("long name identity = %+v", m.Identity)
	}
	if parseListIdentity([]byte{1, 0, 0x0D, 0, 0, 0}) != nil {
		t.Fatal("wrong item type accepted")
	}
	if parseListIdentity([]byte{1, 0, 0x0C, 0, 4, 0, 1, 2, 3, 4}) != nil {
		t.Fatal("short item accepted")
	}
	if parseListIdentity([]byte{1}) != nil {
		t.Fatal("tiny body accepted")
	}
}

func TestDecodeENIP_CPFEdgeCases(t *testing.T) {
	t.Parallel()
	for name, body := range map[string][]byte{
		"prefix only":         {0, 0, 0, 0},
		"item header cut":     {0, 0, 0, 0, 0, 0, 1, 0, 0xB2},
		"item past capture":   {0, 0, 0, 0, 0, 0, 2, 0, 0x00, 0, 200, 0},
		"no data item":        {0, 0, 0, 0, 0, 0, 1, 0, 0x00, 0, 0, 0},
		"connected too short": {0, 0, 0, 0, 0, 0, 1, 0, 0xB1, 0, 2, 0, 1, 0},
		"cip too short":       {0, 0, 0, 0, 0, 0, 1, 0, 0xB2, 0, 1, 0, 0x0E},
	} {
		m, ok := DecodeENIP(enipFrame(enipSendRRData, 0, body...), false)
		if !ok || m.FunctionName != "send_rr_data" || m.Class != ClassOther {
			t.Fatalf("%s: %+v ok=%v", name, m, ok)
		}
	}
}

func TestDecodeENIP_Rejects(t *testing.T) {
	t.Parallel()
	opts := enipFrame(enipRegister, 0)
	opts[20] = 1
	tests := map[string]struct {
		frame    []byte
		response bool
	}{
		"empty":               {nil, false},
		"zero padded (NOP)":   {make([]byte, 128), false},
		"unknown command":     {enipFrame(0x0099, 0), false},
		"options set":         {opts, false},
		"request with status": {enipFrame(enipRegister, 1), false},
		"modbus on 44818":     {mbap(1, 0x03, 0, 0, 0, 1), false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeENIP(tt.frame, tt.response); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
	big := enipFrame(enipRegister, 0)
	binary.LittleEndian.PutUint16(big[2:4], 65535)
	if _, ok := DecodeENIP(big, false); ok {
		t.Fatal("accepted length above the maximum")
	}
}

func TestDecode_DispatchENIP(t *testing.T) {
	t.Parallel()
	if m, ok := Decode(17, 44818, 50000, listIdentityReply("x")); !ok || !m.Response || m.Identity == nil {
		t.Fatalf("udp reply: %+v ok=%v", m, ok)
	}
	if m, ok := Decode(6, 50000, 44818, rrData(0x0E, 0x01, 0x20, 0x01)); !ok || m.Response {
		t.Fatalf("tcp request: %+v ok=%v", m, ok)
	}
}

func TestCleanString(t *testing.T) {
	t.Parallel()
	if got := cleanString([]byte("ok\x00\n\x7fé")); got != "ok" {
		t.Fatalf("got %q", got)
	}
	if got := cleanString([]byte(strings.Repeat("x", 100))); len(got) != maxWireString {
		t.Fatalf("len = %d", len(got))
	}
}

func FuzzDecodeENIP(f *testing.F) {
	f.Add(listIdentityReply("1756-L83E"), true)
	f.Add(rrData(0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x0A, 0x0E, 4, 0, 0x4D, 0x01, 0x91, 0x00), false)
	f.Add(unitData(0x4C, 0x01, 0x20, 0x6B), false)
	f.Fuzz(func(t *testing.T, p []byte, response bool) {
		m, ok := DecodeENIP(p, response)
		if !ok {
			return
		}
		if m.FunctionName == "" || m.Class == "" {
			t.Fatalf("bad message %+v", m)
		}
		if m.Identity != nil && (len(m.Identity.Model) > maxWireString || strings.ContainsAny(m.Identity.Model, "\x00\n\r")) {
			t.Fatalf("unclean identity %+v", m.Identity)
		}
	})
}

func TestCIPPathClass(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		path []byte
		want uint16
	}{
		"8-bit class":                 {[]byte{0x20, 0x06}, 6},
		"instance then class":         {[]byte{0x24, 0x01, 0x20, 0x02}, 2},
		"attribute then class":        {[]byte{0x30, 0x01, 0x20, 0x03}, 3},
		"16-bit attribute then class": {[]byte{0x31, 0x00, 0x01, 0x00, 0x20, 0x04}, 4},
		"16-bit class":                {[]byte{0x21, 0x00, 0x00, 0x01}, 256},
		"truncated 16-bit class":      {[]byte{0x21, 0x00}, 0},
		"truncated 16-bit instance":   {[]byte{0x25, 0x00}, 0},
		"symbolic":                    {[]byte{0x91, 0x02, 'a', 'b'}, 0},
		"empty":                       {nil, 0},
	}
	for name, tt := range tests {
		if got := cipPathClass(tt.path); got != tt.want {
			t.Errorf("%s: got %d, want %d", name, got, tt.want)
		}
	}
}

func TestParseListIdentity_ItemShorterThanBody(t *testing.T) {
	t.Parallel()
	f := listIdentityReply("PLC-7")
	// Trailing bytes after the item must not be read as part of it.
	body := f[24 : 24+int(binary.LittleEndian.Uint16(f[2:4]))]
	body = append(append([]byte(nil), body...), 0xEE, 0xEE)
	id := parseListIdentity(body)
	if id == nil || id.Model != "PLC-7" {
		t.Fatalf("identity = %+v", id)
	}
}
