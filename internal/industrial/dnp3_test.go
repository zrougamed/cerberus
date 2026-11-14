package industrial

import (
	"encoding/binary"
	"testing"
)

// dnp3Frame builds a link header (with a valid CRC) plus the start of the
// first data block. Block CRCs are not checked by the decoder, so they are
// left out.
func dnp3Frame(control byte, dest, src uint16, block ...byte) []byte {
	length := byte(5 + len(block))
	h := []byte{0x05, 0x64, length, control, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[4:6], dest)
	binary.LittleEndian.PutUint16(h[6:8], src)
	h = binary.LittleEndian.AppendUint16(h, dnp3CRC(h))
	out := make([]byte, 128)
	copy(out, append(h, block...))
	return out
}

// master 1 -> outstation 10, PRM set, unconfirmed user data.
func dnp3Request(fc byte) []byte { return dnp3Frame(0xC4, 10, 1, 0xC0, 0xC1, fc) }

func TestDNP3CRC_KnownVector(t *testing.T) {
	t.Parallel()
	// Reset-link frame from IEEE 1815 examples: 05 64 05 C0 01 00 00 04 E9 21.
	if got := dnp3CRC([]byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04}); got != 0x21E9 {
		t.Fatalf("crc = %#04x, want 0x21e9", got)
	}
}

func TestDecodeDNP3_Requests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fc    byte
		name  string
		class Class
	}{
		{1, "read", ClassRead},
		{2, "write", ClassWrite},
		{3, "select", ClassControl},
		{4, "operate", ClassControl},
		{5, "direct_operate", ClassControl},
		{6, "direct_operate_no_ack", ClassControl},
		{13, "cold_restart", ClassDiagnostic},
		{14, "warm_restart", ClassDiagnostic},
		{18, "stop_application", ClassControl},
		{21, "disable_unsolicited", ClassDiagnostic},
		{27, "delete_file", ClassProgram},
		{99, "unknown", ClassOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeDNP3(dnp3Request(tt.fc))
			if !ok || m.Protocol != ProtocolDNP3 || m.FunctionName != tt.name || m.Class != tt.class || m.Response {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
			if m.Detail != "outstation 10" {
				t.Fatalf("detail = %q", m.Detail)
			}
		})
	}
}

func TestDecodeDNP3_Responses(t *testing.T) {
	t.Parallel()
	// outstation 10 -> master 1, response with IIN1=0x00 IIN2=0x00.
	m, ok := DecodeDNP3(dnp3Frame(0x44, 1, 10, 0xC0, 0xC1, 129, 0x00, 0x00))
	if !ok || !m.Response || m.FunctionName != "response" || m.Exception != 0 || m.Detail != "outstation 10" {
		t.Fatalf("response: %+v ok=%v", m, ok)
	}
	// IIN2 bit 0: function code not supported.
	m, ok = DecodeDNP3(dnp3Frame(0x44, 1, 10, 0xC0, 0xC1, 129, 0x00, 0x01))
	if !ok || m.Exception != 1 {
		t.Fatalf("error response: %+v ok=%v", m, ok)
	}
	m, ok = DecodeDNP3(dnp3Frame(0x44, 1, 10, 0xC0, 0xC1, 130, 0x10, 0x00))
	if !ok || m.FunctionName != "unsolicited_response" || !m.Response {
		t.Fatalf("unsolicited: %+v ok=%v", m, ok)
	}
	// Authentication responses carry no IIN error semantics.
	m, ok = DecodeDNP3(dnp3Frame(0x44, 1, 10, 0xC0, 0xC1, 131, 0xFF, 0xFF))
	if !ok || m.Exception != 0 {
		t.Fatalf("auth response: %+v ok=%v", m, ok)
	}
}

func TestDecodeDNP3_LinkLayerOnly(t *testing.T) {
	t.Parallel()
	for name, frame := range map[string][]byte{
		"reset link":       dnp3Frame(0xC0, 1, 1024),
		"link status":      dnp3Frame(0xC9, 1, 1024),
		"secondary to pri": dnp3Frame(0x0B, 1024, 1),
	} {
		m, ok := DecodeDNP3(frame)
		if !ok || m.FunctionName != "link_layer" || m.Detail != "" {
			t.Fatalf("%s: %+v ok=%v", name, m, ok)
		}
	}
}

func TestDecodeDNP3_Rejects(t *testing.T) {
	t.Parallel()
	bad := dnp3Request(5)
	bad[9] ^= 0xFF
	short := dnp3Frame(0xC4, 10, 1, 0xC0, 0xC1, 5)[:12]
	lowLen := dnp3Request(5)
	lowLen[2] = 4
	tests := map[string][]byte{
		"empty":                nil,
		"zero padded":          make([]byte, 128),
		"wrong start":          append([]byte{0x05, 0x65}, dnp3Request(5)[2:]...),
		"bad header crc":       bad,
		"length below minimum": lowLen,
		"user data cut off":    short,
		"modbus on 20000":      mbap(1, 0x06, 0, 1, 0, 3),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeDNP3(frame); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
}

func TestDecode_DispatchDNP3(t *testing.T) {
	t.Parallel()
	for _, proto := range []uint8{6, 17} {
		if m, ok := Decode(proto, 50000, 20000, dnp3Request(5)); !ok || m.Protocol != ProtocolDNP3 {
			t.Fatalf("proto %d: %+v ok=%v", proto, m, ok)
		}
	}
	if _, ok := Decode(1, 50000, 20000, dnp3Request(5)); ok {
		t.Fatal("ICMP dispatched to DNP3")
	}
}

func FuzzDecodeDNP3(f *testing.F) {
	f.Add(dnp3Request(5))
	f.Add(dnp3Frame(0x44, 1, 10, 0xC0, 0xC1, 129, 0, 1))
	f.Add(dnp3Frame(0xC0, 1, 1024))
	f.Fuzz(func(t *testing.T, p []byte) {
		m, ok := DecodeDNP3(p)
		if ok && (m.Protocol != ProtocolDNP3 || m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
