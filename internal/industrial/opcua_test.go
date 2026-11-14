package industrial

import (
	"encoding/binary"
	"testing"
)

func opcuaFrame(typ string, chunk byte, body ...byte) []byte {
	h := append([]byte(typ), chunk, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(h[4:8], uint32(8+len(body)))
	out := make([]byte, 128)
	copy(out, append(h, body...))
	return out
}

func opn(policy string) []byte {
	uri := "http://opcfoundation.org/UA/SecurityPolicy#" + policy
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(uri)))
	return opcuaFrame("OPN", 'F', append(b, uri...)...)
}

// msg builds a MSG chunk whose body starts with the given NodeId bytes.
func msg(nodeID ...byte) []byte {
	return opcuaFrame("MSG", 'F', append(make([]byte, 16), nodeID...)...)
}

func TestDecodeOPCUA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		frame    []byte
		response bool
		fn       string
		class    Class
		detail   string
		flag     string
	}{
		{"hello", opcuaFrame("HEL", 'F', 0, 0, 0, 0), false, "hello", ClassOther, "", ""},
		{"open with None", opn("None"), false, "open_secure_channel", ClassOther, "security policy None", FlagInsecurePolicy},
		{"open with Basic256Sha256", opn("Basic256Sha256"), false, "open_secure_channel", ClassOther, "security policy Basic256Sha256", ""},
		{"open reply with None is not flagged", opn("None"), true, "open_secure_channel", ClassOther, "security policy None", ""},
		{"write request four-byte id", msg(0x01, 0x00, 0xA1, 0x02), false, "write", ClassWrite, "", ""},
		{"read request numeric id", msg(0x02, 0x00, 0x00, 0x77, 0x02, 0x00, 0x00), false, "read", ClassRead, "", ""},
		{"call request", msg(0x01, 0x00, 0xC8, 0x02), false, "call", ClassControl, "", ""},
		{"write response", msg(0x01, 0x00, 0xA4, 0x02), true, "write_response", ClassOther, "", ""},
		{"two-byte id unknown", msg(0x00, 0x10), false, "message", ClassOther, "", ""},
		{"encrypted body", msg(0x9F, 0x3A, 0x11, 0x02), false, "message", ClassOther, "", ""},
		{"four-byte id other namespace", msg(0x01, 0x02, 0xA1, 0x02), false, "message", ClassOther, "", ""},
		{"numeric id other namespace", msg(0x02, 0x01, 0x00, 0x77, 0x02, 0x00, 0x00), false, "message", ClassOther, "", ""},
		{"intermediate chunk", opcuaFrame("MSG", 'C'), false, "message", ClassOther, "", ""},
		{"close", opcuaFrame("CLO", 'F'), false, "close_secure_channel", ClassOther, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeOPCUA(tt.frame, tt.response)
			if !ok || m.Protocol != ProtocolOPCUA || m.FunctionName != tt.fn || m.Class != tt.class || m.Detail != tt.detail || m.Flag != tt.flag {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
		})
	}
	m, ok := DecodeOPCUA(opcuaFrame("ERR", 'F', 0, 0, 0x80, 0x80), true)
	if !ok || m.Exception != 1 {
		t.Fatalf("error: %+v ok=%v", m, ok)
	}
}

func TestOPCUAPolicyAndTypeID_Edges(t *testing.T) {
	t.Parallel()
	for name, b := range map[string][]byte{
		"short":            {0, 0, 0, 0},
		"null uri":         {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF},
		"uri past capture": {0, 0, 0, 0, 50, 0, 0, 0, 'h'},
		"no fragment":      append([]byte{0, 0, 0, 0, 4, 0, 0, 0}, "abcd"...),
		"empty fragment":   append([]byte{0, 0, 0, 0, 2, 0, 0, 0}, "a#"...),
	} {
		if p, ok := opcuaPolicy(b); ok {
			t.Errorf("policy %s: got %q", name, p)
		}
	}
	for name, b := range map[string][]byte{
		"short":         make([]byte, 17),
		"four-byte cut": append(make([]byte, 16), 0x01, 0x00, 0xA1),
		"numeric cut":   append(make([]byte, 16), 0x02, 0x00, 0x00, 0x77),
	} {
		if id, ok := opcuaTypeID(b); ok {
			t.Errorf("type id %s: got %d", name, id)
		}
	}
}

func TestDecodeOPCUA_Rejects(t *testing.T) {
	t.Parallel()
	small := opcuaFrame("HEL", 'F')
	binary.LittleEndian.PutUint32(small[4:8], 4)
	huge := opcuaFrame("HEL", 'F')
	binary.LittleEndian.PutUint32(huge[4:8], 1<<30)
	tests := map[string][]byte{
		"empty":            nil,
		"zero padded":      make([]byte, 128),
		"unknown type":     opcuaFrame("XYZ", 'F'),
		"bad chunk type":   opcuaFrame("MSG", 'X'),
		"size below 8":     small,
		"size above limit": huge,
		"http on 4840":     []byte("GET / HTTP/1.1\r\n\r\n"),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeOPCUA(frame, false); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
}

func FuzzDecodeOPCUA(f *testing.F) {
	f.Add(opn("None"), false)
	f.Add(msg(0x01, 0x00, 0xA1, 0x02), false)
	f.Fuzz(func(t *testing.T, p []byte, response bool) {
		if m, ok := DecodeOPCUA(p, response); ok && (m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
