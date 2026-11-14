package industrial

import "testing"

// tpkt wraps a COTP TPDU in a TPKT header, zero-padded to the capture size.
func tpkt(cotp ...byte) []byte {
	n := 4 + len(cotp)
	out := make([]byte, 128)
	copy(out, append([]byte{3, 0, byte(n >> 8), byte(n)}, cotp...))
	return out
}

// s7dt builds TPKT + COTP DT + an S7 PDU.
func s7dt(pdu ...byte) []byte {
	return tpkt(append([]byte{0x02, 0xF0, 0x80}, pdu...)...)
}

// s7job builds an S7 Job header followed by params.
func s7job(params ...byte) []byte {
	n := len(params)
	return append([]byte{0x32, s7RosctrJob, 0, 0, 0, 1, byte(n >> 8), byte(n), 0, 0}, params...)
}

func s7ackData(errClass byte, params ...byte) []byte {
	n := len(params)
	return append([]byte{0x32, s7RosctrAckData, 0, 0, 0, 1, byte(n >> 8), byte(n), 0, 0, errClass, 0}, params...)
}

// COTP connection request from an engineering tool to rack 0, slot 2.
var cotpCR = tpkt(0x11, 0xE0, 0, 0, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2)

func TestDecodeS7_Jobs(t *testing.T) {
	t.Parallel()
	piStart := []byte{0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 9, 'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M'}
	piDelete := []byte{0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 10, 1, 0, '0', 'A', '0', '0', '0', '0', '1', 'B', 5, '_', 'D', 'E', 'L', 'E'}
	piUnknown := []byte{0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 5, '_', 'N', 'O', 'P', 'E'}
	tests := []struct {
		name  string
		frame []byte
		fn    string
		class Class
	}{
		{"setup communication", s7dt(s7job(0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0)...), "setup_communication", ClassOther},
		{"read var", s7dt(s7job(0x04, 1, 0x12, 0x0A, 0x10, 2, 0, 1, 0, 1, 0x84, 0, 0, 0)...), "read_var", ClassRead},
		{"write var", s7dt(s7job(0x05, 1, 0x12, 0x0A, 0x10, 2, 0, 1, 0, 1, 0x84, 0, 0, 0)...), "write_var", ClassWrite},
		{"request download", s7dt(s7job(0x1A, 0, 0, 0, 0, 0, 0, 0, 0)...), "request_download", ClassProgram},
		{"download block", s7dt(s7job(0x1B, 0, 0, 0, 0, 0, 0, 0, 0)...), "download_block", ClassProgram},
		{"upload", s7dt(s7job(0x1E, 0, 0, 0, 0, 0, 0, 0)...), "upload", ClassRead},
		{"plc stop", s7dt(s7job(0x29, 0, 0, 0, 0, 0, 9, 'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M')...), "plc_stop", ClassControl},
		{"plc start via PI service", s7dt(s7job(piStart...)...), "plc_start", ClassControl},
		{"delete block via PI service", s7dt(s7job(piDelete...)...), "delete_block", ClassProgram},
		{"unknown PI service stays generic", s7dt(s7job(piUnknown...)...), "pi_service", ClassControl},
		{"truncated PI service stays generic", s7dt(s7job(0x28, 0, 0)...), "pi_service", ClassControl},
		{"PI block length past the capture", s7dt(s7job(0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 90, 1)...), "pi_service", ClassControl},
		{"PI name length past the capture", s7dt(s7job(0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 40, 'P')...), "pi_service", ClassControl},
		{"unknown function", s7dt(s7job(0x77)...), "unknown", ClassOther},
		// Param length 2 covers only "05 01"; the data section that follows
		// must not be read as parameters.
		{"write var with data section", s7dt(append(s7job(0x05, 1), 0x00, 0x04, 0x00, 0x10, 0xBE, 0xEF)...), "write_var", ClassWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeS7(tt.frame, false)
			if !ok {
				t.Fatal("expected a valid S7 frame")
			}
			if m.Protocol != ProtocolS7 || m.FunctionName != tt.fn || m.Class != tt.class || m.Response {
				t.Fatalf("got %+v, want s7comm/%s/%s request", m, tt.fn, tt.class)
			}
			if m.HasUnit || m.HasRange {
				t.Fatalf("S7 message claims a unit or range: %+v", m)
			}
		})
	}
}

func TestDecodeS7_ResponsesUseHeaderDirection(t *testing.T) {
	t.Parallel()
	// Port direction says request, but ROSCTR says Ack_Data: trust the header.
	m, ok := DecodeS7(s7dt(s7ackData(0, 0x05, 1)...), false)
	if !ok || !m.Response || m.FunctionName != "write_var" || m.Exception != 0 {
		t.Fatalf("ack data: %+v ok=%v", m, ok)
	}
	m, ok = DecodeS7(s7dt(s7ackData(0x85, 0x29)...), true)
	if !ok || m.Exception != 0x85 || m.FunctionName != "plc_stop" {
		t.Fatalf("error ack: %+v ok=%v", m, ok)
	}
	// A PI-service reply is not reinterpreted from a request layout.
	m, ok = DecodeS7(s7dt(s7ackData(0, 0x28)...), true)
	if !ok || m.FunctionName != "pi_service" {
		t.Fatalf("pi ack: %+v ok=%v", m, ok)
	}
	ack := []byte{0x32, s7RosctrAck, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	m, ok = DecodeS7(s7dt(ack...), true)
	if !ok || !m.Response || m.FunctionName != "ack" {
		t.Fatalf("bare ack: %+v ok=%v", m, ok)
	}
}

func TestDecodeS7_Userdata(t *testing.T) {
	t.Parallel()
	ud := []byte{0x32, s7RosctrUserdata, 0, 0, 0, 1, 0, 8, 0, 4, 0, 1, 0x12, 4, 0x11, 0x44, 1, 0}
	for _, response := range []bool{false, true} {
		m, ok := DecodeS7(s7dt(ud...), response)
		if !ok || m.FunctionName != "userdata" || m.Class != ClassOther || m.Response != response {
			t.Fatalf("userdata response=%v: %+v ok=%v", response, m, ok)
		}
	}
}

func TestDecodeS7_COTPConnect(t *testing.T) {
	t.Parallel()
	m, ok := DecodeS7(cotpCR, false)
	if !ok || m.FunctionName != "cotp_connect" || m.Detail != "rack 0 slot 2" || m.Response {
		t.Fatalf("CR: %+v ok=%v", m, ok)
	}
	cc := tpkt(0x11, 0xD0, 0, 1, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 3, 0x23)
	m, ok = DecodeS7(cc, false)
	if !ok || m.FunctionName != "cotp_connect_confirm" || !m.Response || m.Detail != "rack 1 slot 3" {
		t.Fatalf("CC: %+v ok=%v", m, ok)
	}
}

func TestDecodeS7_S7CommPlus(t *testing.T) {
	t.Parallel()
	m, ok := DecodeS7(s7dt(0x72, 0x03, 0x00, 0x1F), false)
	if !ok || m.Protocol != ProtocolS7Plus || m.FunctionName != "s7comm_plus" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
	if _, ok := DecodeS7(s7dt(0x72, 0x09), false); ok {
		t.Fatal("accepted S7comm-plus with an impossible version")
	}
}

func TestDecodeS7_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"zero padded ack", make([]byte, 128)},
		{"wrong TPKT version", func() []byte { f := s7dt(s7job(0x04)...); f[0] = 2; return f }()},
		{"TPKT shorter than COTP", func() []byte { f := s7dt(s7job(0x04)...); f[3] = 5; return f }()},
		{"COTP length below DT minimum", tpkt(0x01, 0xF0)},
		{"COTP longer than capture", []byte{3, 0, 0, 40, 30, 0xF0, 0x80}},
		{"DT with wrong length", tpkt(0x03, 0xF0, 0x80, 0x00, 0x32)},
		{"disconnect request", tpkt(0x06, 0x80, 0, 1, 0, 1, 0)},
		{"MMS connect (TSAP 0001)", tpkt(0x11, 0xE0, 0, 0, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 0, 1, 0xC2, 2, 0, 1)},
		{"connect without TSAP", tpkt(0x06, 0xE0, 0, 0, 0, 1, 0)},
		{"connect too short", tpkt(0x03, 0xE0, 0, 0)},
		{"connect param overruns", tpkt(0x09, 0xE0, 0, 0, 0, 1, 0, 0xC2, 9, 1)},
		{"MMS session data", s7dt(0x01, 0x00, 0x01, 0x00)},
		{"S7 PDU too short", s7dt(0x32)},
		{"S7 header truncated", s7dt(0x32, 1, 0, 0)},
		{"reserved bytes set", s7dt(0x32, 1, 0, 1, 0, 1, 0, 0, 0, 0)},
		{"unknown ROSCTR", s7dt(0x32, 5, 0, 0, 0, 1, 0, 0, 0, 0)},
		{"ack data header truncated", s7dt(0x32, 3, 0, 0, 0, 1, 0, 0, 0, 0)},
		{"job without parameters", s7dt(s7job()...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeS7(tt.frame, false); ok {
				t.Fatalf("accepted invalid frame as %+v", m)
			}
		})
	}
}

func TestDecode_DispatchS7(t *testing.T) {
	t.Parallel()
	if m, ok := Decode(6, 49152, 102, cotpCR); !ok || m.Protocol != ProtocolS7 {
		t.Fatalf("client to 102: %+v ok=%v", m, ok)
	}
	if m, ok := Decode(6, 102, 49152, s7dt(0x72, 1)); !ok || !m.Response {
		t.Fatalf("server to client: %+v ok=%v", m, ok)
	}
	if _, ok := Decode(17, 49152, 102, cotpCR); ok {
		t.Fatal("UDP 102 is not ISO-on-TCP")
	}
}

func FuzzDecodeS7(f *testing.F) {
	f.Add(cotpCR, false)
	f.Add(s7dt(s7job(0x05, 1, 0x12)...), false)
	f.Add(s7dt(s7job(0x28, 0, 0, 0, 0, 0, 0, 0xFD, 0, 0, 9, 'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M')...), false)
	f.Add(s7dt(s7ackData(0x85, 0x29)...), true)
	f.Add(s7dt(0x72, 3), true)
	f.Fuzz(func(t *testing.T, p []byte, response bool) {
		m, ok := DecodeS7(p, response)
		if !ok {
			return
		}
		if m.Protocol != ProtocolS7 && m.Protocol != ProtocolS7Plus {
			t.Fatalf("wrong protocol: %+v", m)
		}
		if m.FunctionName == "" || m.Class == "" {
			t.Fatalf("unclassified message: %+v", m)
		}
	})
}
