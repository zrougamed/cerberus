package industrial

import (
	"encoding/binary"
	"testing"
)

type dcpTLV struct {
	opt, sub uint8
	data     []byte
}

// dcp builds a DCP frame from the frame id on.
func dcp(frameID uint16, service, stype uint8, blocks ...dcpTLV) []byte {
	var body []byte
	for _, b := range blocks {
		body = append(body, b.opt, b.sub)
		body = binary.BigEndian.AppendUint16(body, uint16(len(b.data)))
		body = append(body, b.data...)
		if len(b.data)%2 == 1 {
			body = append(body, 0)
		}
	}
	p := binary.BigEndian.AppendUint16(nil, frameID)
	p = append(p, service, stype, 0, 0, 0, 7, 0, 0)
	p = binary.BigEndian.AppendUint16(p, uint16(len(body)))
	out := make([]byte, 128)
	copy(out, append(p, body...))
	return out
}

// withInfo prefixes a block value with a 2-byte BlockInfo/BlockQualifier.
func withInfo(v ...byte) []byte { return append([]byte{0, 0}, v...) }

func TestDecodeDCP_IdentifyResponse(t *testing.T) {
	t.Parallel()
	frame := dcp(0xFEFF, 3, 1,
		dcpTLV{2, 1, withInfo([]byte("S7-1500")...)},
		dcpTLV{2, 2, withInfo([]byte("plc-line1")...)},
		dcpTLV{2, 3, withInfo(0x00, 0x2A, 0x01, 0x0E)},
		dcpTLV{1, 2, withInfo(10, 20, 0, 50, 255, 255, 255, 0, 10, 20, 0, 1)},
	)
	m, ok := DecodeDCP(frame)
	if !ok || m.Protocol != ProtocolProfinet || m.FunctionName != "identify" || !m.Response || m.Detail != "station plc-line1" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
	want := Identity{Vendor: "Siemens AG", Model: "S7-1500", DeviceType: "PROFINET device 0x010e"}
	if m.Identity == nil || *m.Identity != want {
		t.Fatalf("identity = %+v", m.Identity)
	}
	// Unknown vendor id, no station name.
	m, _ = DecodeDCP(dcp(0xFEFF, 3, 1, dcpTLV{2, 3, withInfo(0x01, 0x23, 0, 1)}))
	if m.Identity.Vendor != "PROFINET vendor 0x0123" || m.Detail != "" {
		t.Fatalf("unknown vendor: %+v / %q", m.Identity, m.Detail)
	}
}

func TestDecodeDCP_SetRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		blocks []dcpTLV
		fn     string
		class  Class
		detail string
	}{
		{"rename station", []dcpTLV{{2, 2, withInfo([]byte("evil")...)}}, "set_name", ClassWrite, "new name evil"},
		{"change address", []dcpTLV{{1, 2, withInfo(192, 168, 0, 9, 255, 255, 255, 0, 0, 0, 0, 0)}}, "set_ip", ClassWrite, "new address 192.168.0.9"},
		{"factory reset", []dcpTLV{{2, 2, withInfo('x')}, {5, 6, withInfo(0, 2)}}, "set_factory_reset", ClassControl, ""},
		{"reset factory settings", []dcpTLV{{5, 5, withInfo(0, 1)}}, "set_factory_reset", ClassControl, ""},
		{"flash led", []dcpTLV{{5, 3, withInfo(0, 0x01, 0, 0x00)}}, "set_signal", ClassOther, ""},
		{"start transaction only", []dcpTLV{{5, 1, withInfo()}}, "set", ClassOther, ""},
		{"block without qualifier", []dcpTLV{{2, 2, []byte{0}}}, "set", ClassOther, ""},
		{"address cut short", []dcpTLV{{1, 2, withInfo(10, 0)}}, "set_ip", ClassWrite, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeDCP(dcp(0xFEFD, 2, 0, tt.blocks...))
			if !ok || m.FunctionName != tt.fn || m.Class != tt.class || m.Detail != tt.detail || m.Response {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
		})
	}
}

func TestDecodeDCP_OtherServices(t *testing.T) {
	t.Parallel()
	if m, ok := DecodeDCP(dcp(0xFEFE, 3, 0, dcpTLV{0xFF, 0xFF, nil})); !ok || m.FunctionName != "identify" || m.Response || m.Identity != nil {
		t.Fatalf("identify request: %+v", m)
	}
	m, ok := DecodeDCP(dcp(0xFEFC, 4, 0, dcpTLV{2, 2, withInfo([]byte("io-1")...)}))
	if !ok || m.FunctionName != "hello" || !m.Response || m.Detail != "station io-1" {
		t.Fatalf("hello: %+v", m)
	}
	if m, _ := DecodeDCP(dcp(0xFEFD, 1, 0)); m.FunctionName != "get" || m.Class != ClassOther {
		t.Fatalf("get: %+v", m)
	}
	m, _ = DecodeDCP(dcp(0xFEFD, 2, 5))
	if m.FunctionName != "set" || !m.Response || m.Exception != 5 {
		t.Fatalf("set not supported: %+v", m)
	}
}

func TestDecodeDCP_Rejects(t *testing.T) {
	t.Parallel()
	for name, frame := range map[string][]byte{
		"short":           {0xFE, 0xFE, 3},
		"cyclic frame id": dcp(0x8000, 3, 0),
		"unknown service": dcp(0xFEFE, 9, 0),
		"zero service":    dcp(0xFEFE, 0, 0),
	} {
		if m, ok := DecodeDCP(frame); ok {
			t.Errorf("%s accepted as %+v", name, m)
		}
	}
	// Block length past the data is ignored rather than read.
	b := dcp(0xFEFF, 3, 1, dcpTLV{2, 2, withInfo([]byte("x")...)})
	binary.BigEndian.PutUint16(b[14:16], 200)
	if m, ok := DecodeDCP(b); !ok || m.Detail != "" {
		t.Fatalf("overlong block: %+v ok=%v", m, ok)
	}
}

func TestDecodeDCP_LastBlockWithoutPadding(t *testing.T) {
	t.Parallel()
	// A 3-byte value would be padded to 4; the data length stops before the
	// pad byte, so the block is still read and the walk ends cleanly.
	b := dcp(0xFEFF, 3, 1, dcpTLV{2, 2, withInfo('x')})
	binary.BigEndian.PutUint16(b[10:12], 7)
	if m, ok := DecodeDCP(b); !ok || m.Detail != "station x" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
}

func FuzzDecodeDCP(f *testing.F) {
	f.Add(dcp(0xFEFF, 3, 1, dcpTLV{2, 2, withInfo([]byte("plc")...)}, dcpTLV{2, 3, withInfo(0, 0x2A, 1, 2)}))
	f.Add(dcp(0xFEFD, 2, 0, dcpTLV{1, 2, withInfo(10, 0, 0, 1, 255, 0, 0, 0, 0, 0, 0, 0)}, dcpTLV{5, 6, withInfo(0, 2)}))
	f.Fuzz(func(t *testing.T, p []byte) {
		m, ok := DecodeDCP(p)
		if ok && (m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
