package industrial

import (
	"testing"
)

// mbap builds a Modbus/TCP frame zero-padded to the 128-byte capture size.
func mbap(unit byte, pdu ...byte) []byte {
	length := len(pdu) + 1
	frame := []byte{0x12, 0x34, 0x00, 0x00, byte(length >> 8), byte(length), unit}
	frame = append(frame, pdu...)
	out := make([]byte, 128)
	copy(out, frame)
	return out
}

func TestDecodeModbus_Requests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		frame     []byte
		fn        string
		class     Class
		addr, qty uint16
		hasRange  bool
	}{
		{"read holding registers", mbap(1, 0x03, 0x00, 0x6B, 0x00, 0x03), "read_holding_registers", ClassRead, 0x6B, 3, true},
		{"read coils", mbap(1, 0x01, 0x00, 0x13, 0x00, 0x25), "read_coils", ClassRead, 0x13, 0x25, true},
		{"write single coil", mbap(17, 0x05, 0x00, 0xAC, 0xFF, 0x00), "write_single_coil", ClassWrite, 0xAC, 1, true},
		{"write single register", mbap(1, 0x06, 0x00, 0x01, 0x00, 0x03), "write_single_register", ClassWrite, 1, 1, true},
		{"write multiple registers", mbap(1, 0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02), "write_multiple_registers", ClassWrite, 1, 2, true},
		{"write multiple coils", mbap(1, 0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01), "write_multiple_coils", ClassWrite, 0x13, 10, true},
		{"mask write", mbap(1, 0x16, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25), "mask_write_register", ClassWrite, 4, 1, true},
		{"read/write multiple reports write range", mbap(1, 0x17, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x03, 0x06, 0, 0xFF, 0, 0xFF, 0, 0xFF), "read_write_multiple_registers", ClassWrite, 0x0E, 3, true},
		{"diagnostics restart comms", mbap(1, 0x08, 0x00, 0x01, 0x00, 0x00), "diagnostics", ClassDiagnostic, 0, 0, false},
		{"read device identification is a read", mbap(1, 0x2B, 0x0E, 0x01, 0x00), "read_device_identification", ClassRead, 0, 0, false},
		{"other MEI type is diagnostic", mbap(1, 0x2B, 0x0D, 0x00), "encapsulated_interface_transport", ClassDiagnostic, 0, 0, false},
		{"user defined function", mbap(1, 0x41, 0x00), "unknown", ClassOther, 0, 0, false},
		{"read with truncated range", mbap(1, 0x03, 0x00), "read_holding_registers", ClassRead, 0, 0, false},
		{"single write with truncated address", mbap(1, 0x06, 0x00), "write_single_register", ClassWrite, 0, 0, false},
		{"read/write multiple truncated", mbap(1, 0x17, 0x00, 0x03, 0x00, 0x06), "read_write_multiple_registers", ClassWrite, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeModbus(tt.frame, false)
			if !ok {
				t.Fatal("expected a valid Modbus frame")
			}
			if m.Protocol != ProtocolModbus || m.FunctionName != tt.fn || m.Class != tt.class {
				t.Fatalf("got %s/%s/%s, want modbus/%s/%s", m.Protocol, m.FunctionName, m.Class, tt.fn, tt.class)
			}
			if m.HasRange != tt.hasRange || m.Address != tt.addr || m.Quantity != tt.qty {
				t.Fatalf("range = %v %d/%d, want %v %d/%d", m.HasRange, m.Address, m.Quantity, tt.hasRange, tt.addr, tt.qty)
			}
			if m.Response || m.Exception != 0 {
				t.Fatalf("request decoded as response: %+v", m)
			}
		})
	}
}

func TestDecodeModbus_UnitID(t *testing.T) {
	t.Parallel()
	m, ok := DecodeModbus(mbap(247, 0x03, 0, 0, 0, 1), false)
	if !ok || m.Unit != 247 {
		t.Fatalf("unit = %d ok=%v, want 247", m.Unit, ok)
	}
}

func TestDecodeModbus_Responses(t *testing.T) {
	t.Parallel()
	m, ok := DecodeModbus(mbap(1, 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64), true)
	if !ok || !m.Response || m.Exception != 0 || m.HasRange {
		t.Fatalf("normal response: %+v ok=%v", m, ok)
	}

	m, ok = DecodeModbus(mbap(1, 0x86, 0x02), true)
	if !ok || !m.Response || m.Function != 6 || m.FunctionName != "write_single_register" || m.Exception != 2 {
		t.Fatalf("exception response: %+v ok=%v", m, ok)
	}
}

func TestDecodeModbus_ExceptionBitImpliesResponse(t *testing.T) {
	t.Parallel()
	// Seen from the "request" side (dst port 502) an exception PDU is still
	// a reply; it must not be counted as a write request.
	m, ok := DecodeModbus(mbap(1, 0x90, 0x04), false)
	if !ok || !m.Response || m.Class != ClassWrite || m.Exception != 4 {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func TestDecodeModbus_TruncatedExceptionCode(t *testing.T) {
	t.Parallel()
	// Header declares only unit + function, so the exception code is not
	// covered by the length even though the padded buffer has a byte there.
	frame := make([]byte, 128)
	copy(frame, []byte{0, 1, 0, 0, 0, 2, 1, 0x83, 0x02})
	m, ok := DecodeModbus(frame, true)
	if !ok || m.Exception != 0xFF {
		t.Fatalf("exception = %#x ok=%v, want 0xff", m.Exception, ok)
	}
}

func TestDecodeModbus_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"too short", []byte{0, 1, 0, 0, 0, 6, 1}},
		{"zero padded ack", make([]byte, 128)},
		{"wrong protocol id", func() []byte { f := mbap(1, 0x03, 0, 0, 0, 1); f[3] = 1; return f }()},
		{"length below minimum", func() []byte { f := mbap(1, 0x03, 0, 0, 0, 1); f[4], f[5] = 0, 1; return f }()},
		{"length above maximum", func() []byte { f := mbap(1, 0x03, 0, 0, 0, 1); f[4], f[5] = 0, 255; return f }()},
		{"function code zero", mbap(1, 0x00, 0, 0)},
		{"bare exception bit", mbap(1, 0x80, 0x01)},
		{"tls on port 502", append([]byte{0x16, 0x03, 0x01, 0x00, 0xA5, 0x01, 0x00}, make([]byte, 121)...)},
		{"http on port 502", []byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeModbus(tt.frame, false); ok {
				t.Fatalf("accepted invalid frame as %+v", m)
			}
		})
	}
}

func TestDecode_Dispatch(t *testing.T) {
	t.Parallel()
	frame := mbap(1, 0x06, 0, 1, 0, 3)
	tests := []struct {
		name         string
		proto        uint8
		sport, dport uint16
		ok, response bool
	}{
		{"client to server", 6, 50123, 502, true, false},
		{"server to client", 6, 502, 50123, true, true},
		{"502 to 502 is a request", 6, 502, 502, true, false},
		{"udp is not modbus/tcp", 17, 50123, 502, false, false},
		{"other port", 6, 50123, 503, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := Decode(tt.proto, tt.sport, tt.dport, frame)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && m.Response != tt.response {
				t.Fatalf("response = %v, want %v", m.Response, tt.response)
			}
		})
	}
}

func FuzzDecodeModbus(f *testing.F) {
	f.Add(mbap(1, 0x03, 0, 0, 0, 10), false)
	f.Add(mbap(1, 0x10, 0, 1, 0, 2, 4, 0, 1, 0, 2), false)
	f.Add(mbap(1, 0x83, 0x02), true)
	f.Add(mbap(1, 0x2B, 0x0E, 1, 0), false)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, p []byte, response bool) {
		m, ok := DecodeModbus(p, response)
		if !ok {
			return
		}
		if m.Protocol != ProtocolModbus || m.Function == 0 || m.Function >= modbusExceptionBit {
			t.Fatalf("invalid message accepted: %+v", m)
		}
		if m.Class == "" || m.FunctionName == "" {
			t.Fatalf("unclassified message: %+v", m)
		}
		if m.Response && m.HasRange {
			t.Fatalf("response carries a request range: %+v", m)
		}
	})
}
