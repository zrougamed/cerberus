package industrial

import "testing"

// iFrame builds an IEC 104 I-frame with one ASDU header and a 3-byte IOA.
func iFrame(typ, cause byte, ca uint16, extra ...byte) []byte {
	asdu := append([]byte{typ, 0x01, cause, 0x00, byte(ca), byte(ca >> 8), 0x01, 0x00, 0x00}, extra...)
	apdu := append([]byte{0x68, byte(4 + len(asdu)), 0x02, 0x00, 0x04, 0x00}, asdu...)
	out := make([]byte, 128)
	copy(out, apdu)
	return out
}

func uFrame(c1 byte) []byte { return append([]byte{0x68, 0x04, c1, 0, 0, 0}, make([]byte, 122)...) }

func TestDecodeIEC104_IFrames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		frame    []byte
		fn       string
		class    Class
		response bool
		exc      uint8
	}{
		{"single command activation", iFrame(45, 6, 1, 0x81), "single_command", ClassControl, false, 0},
		{"setpoint float", iFrame(50, 6, 1, 0, 0, 0x80, 0x3F, 0), "setpoint_float", ClassControl, false, 0},
		{"command with time tag", iFrame(58, 6, 1, 0x01), "single_command_time", ClassControl, false, 0},
		{"command deactivation", iFrame(45, 8, 1, 0x01), "single_command", ClassControl, false, 0},
		{"activation confirmation", iFrame(45, 7, 1, 0x81), "single_command", ClassOther, true, 0},
		{"negative confirmation", iFrame(45, 7|0x40, 1, 0x81), "single_command", ClassOther, true, 7},
		{"general interrogation", iFrame(100, 6, 1, 0x14), "interrogation", ClassRead, false, 0},
		{"read command", iFrame(102, 5, 1), "read", ClassRead, false, 0},
		{"reset process", iFrame(105, 6, 1, 0x01), "reset_process", ClassDiagnostic, false, 0},
		{"parameter float", iFrame(112, 6, 1), "parameter_float", ClassWrite, false, 0},
		{"spontaneous measurement", iFrame(13, 3, 1, 0, 0, 0x80, 0x3F, 0), "monitor_data", ClassOther, true, 0},
		{"end of initialization", iFrame(70, 4, 1, 0), "end_of_initialization", ClassOther, true, 0},
		{"unknown type", iFrame(90, 6, 1), "type_90", ClassOther, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeIEC104(tt.frame)
			if !ok || m.Protocol != ProtocolIEC104 || m.FunctionName != tt.fn || m.Class != tt.class || m.Response != tt.response || m.Exception != tt.exc {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
			if m.Detail != "common address 1" {
				t.Fatalf("detail = %q", m.Detail)
			}
		})
	}
}

func TestDecodeIEC104_SAndUFrames(t *testing.T) {
	t.Parallel()
	m, ok := DecodeIEC104(append([]byte{0x68, 0x04, 0x01, 0x00, 0x0A, 0x00}, make([]byte, 10)...))
	if !ok || m.FunctionName != "s_frame" {
		t.Fatalf("s-frame: %+v ok=%v", m, ok)
	}
	for c1, want := range map[byte]struct {
		name     string
		response bool
	}{0x07: {"startdt_act", false}, 0x0B: {"startdt_con", true}, 0x13: {"stopdt_act", false}, 0x83: {"testfr_con", true}} {
		m, ok := DecodeIEC104(uFrame(c1))
		if !ok || m.FunctionName != want.name || m.Response != want.response {
			t.Fatalf("u-frame %#x: %+v ok=%v", c1, m, ok)
		}
	}
}

func TestDecodeIEC104_Rejects(t *testing.T) {
	t.Parallel()
	tests := map[string][]byte{
		"empty":             nil,
		"zero padded":       make([]byte, 128),
		"wrong start":       append([]byte{0x69}, uFrame(0x07)[1:]...),
		"length below 4":    {0x68, 0x03, 0x07, 0, 0, 0},
		"length above 253":  {0x68, 0xFE, 0x07, 0, 0, 0},
		"i-frame no asdu":   {0x68, 0x04, 0x02, 0x00, 0x04, 0x00},
		"i-frame odd recv":  func() []byte { f := iFrame(45, 6, 1); f[4] = 0x05; return f }(),
		"i-frame cut asdu":  {0x68, 0x0E, 0x02, 0x00, 0x04, 0x00, 45, 1},
		"type zero":         iFrame(0, 6, 1),
		"cause zero":        iFrame(45, 0, 1),
		"s-frame bad c1":    {0x68, 0x04, 0x05, 0x00, 0x0A, 0x00},
		"s-frame long":      {0x68, 0x06, 0x01, 0x00, 0x0A, 0x00},
		"unknown u-frame":   uFrame(0x0F),
		"u-frame with data": {0x68, 0x04, 0x07, 0x01, 0, 0},
		"u-frame long":      {0x68, 0x06, 0x07, 0x00, 0, 0},
		"mqtt on 2404":      {0x10, 0x0C, 0x00, 0x04, 'M', 'Q', 'T', 'T', 4, 2, 0, 60},
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeIEC104(frame); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
}

func FuzzDecodeIEC104(f *testing.F) {
	f.Add(iFrame(45, 6, 1, 0x81))
	f.Add(uFrame(0x07))
	f.Add(iFrame(13, 3, 7))
	f.Fuzz(func(t *testing.T, p []byte) {
		if m, ok := DecodeIEC104(p); ok && (m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
