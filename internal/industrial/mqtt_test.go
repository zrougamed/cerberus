package industrial

import (
	"strings"
	"testing"
)

func mqttPacket(first byte, body ...byte) []byte {
	var rl []byte
	n := len(body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		rl = append(rl, b)
		if n == 0 {
			break
		}
	}
	out := make([]byte, max(128, 1+len(rl)+len(body)))
	copy(out, append(append([]byte{first}, rl...), body...))
	return out
}

func connectBody(level, flags byte, props []byte, clientID string) []byte {
	b := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', level, flags, 0x00, 0x3C}
	if level == 5 {
		b = append(b, props...)
	}
	b = append(b, byte(len(clientID)>>8), byte(len(clientID)))
	return append(b, clientID...)
}

func TestDecodeMQTT(t *testing.T) {
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
		{"anonymous connect", mqttPacket(0x10, connectBody(4, 0x02, nil, "sensor-1")...), false, "connect", ClassOther, "client sensor-1", FlagNoUsername},
		{"connect with username", mqttPacket(0x10, connectBody(4, 0xC2, nil, "hmi")...), false, "connect", ClassOther, "client hmi", ""},
		{"v5 connect with properties", mqttPacket(0x10, connectBody(5, 0x82, []byte{0x03, 0x21, 0x00, 0x14}, "plc")...), false, "connect", ClassOther, "client plc", ""},
		{"v5 connect properties cut", mqttPacket(0x10, connectBody(5, 0x82, []byte{0x40}, "")[:11]...), false, "connect", ClassOther, "", ""},
		{"v3.1 connect empty client id", mqttPacket(0x10, append([]byte{0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 3, 0x02, 0, 60}, 0, 0)...), false, "connect", ClassOther, "", FlagNoUsername},
		{"publish", mqttPacket(0x30, append([]byte{0x00, 0x0A}, "plant/line"...)...), false, "publish", ClassWrite, "topic plant/line", ""},
		{"publish qos1 from broker", mqttPacket(0x32, append([]byte{0x00, 0x03}, "a/b"...)...), true, "publish", ClassOther, "topic a/b", ""},
		{"publish topic cut", mqttPacket(0x30, 0x00, 0x40, 'a'), false, "publish", ClassWrite, "", ""},
		{"subscribe", mqttPacket(0x82, 0x00, 0x01, 0x00, 0x01, '#', 0x00), false, "subscribe", ClassRead, "", ""},
		{"pingreq", mqttPacket(0xC0), false, "pingreq", ClassOther, "", ""},
		{"disconnect", mqttPacket(0xE0), false, "disconnect", ClassOther, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, ok := DecodeMQTT(tt.frame, tt.response)
			if !ok || m.Protocol != ProtocolMQTT || m.FunctionName != tt.fn || m.Class != tt.class || m.Detail != tt.detail || m.Flag != tt.flag {
				t.Fatalf("got %+v ok=%v", m, ok)
			}
		})
	}
	m, ok := DecodeMQTT(mqttPacket(0x20, 0x00, 0x05), true)
	if !ok || m.Exception != 5 || !m.Response {
		t.Fatalf("connack refused: %+v ok=%v", m, ok)
	}
	m, _ = DecodeMQTT(mqttPacket(0x20, 0x00, 0x00), true)
	if m.Exception != 0 {
		t.Fatalf("connack accepted: %+v", m)
	}
	// Multi-byte remaining length.
	long := mqttPacket(0x30, append([]byte{0x00, 0x03, 'a', '/', 'b'}, make([]byte, 200)...)...)
	if m, ok := DecodeMQTT(long, false); !ok || m.Detail != "topic a/b" {
		t.Fatalf("long publish: %+v ok=%v", m, ok)
	}
	// Topics are cleaned.
	if m, _ := DecodeMQTT(mqttPacket(0x30, append([]byte{0x00, 0x05}, "x\x1b[y"...)...), false); strings.ContainsRune(m.Detail, 0x1b) {
		t.Fatalf("unclean topic %q", m.Detail)
	}
}

func TestDecodeMQTT_Rejects(t *testing.T) {
	t.Parallel()
	tests := map[string][]byte{
		"empty":                 nil,
		"one byte":              {0x10},
		"zero padded":           make([]byte, 128),
		"publish qos 3":         mqttPacket(0x36, 0, 1, 'a'),
		"subscribe bad flags":   mqttPacket(0x80, 0, 1),
		"connect bad flags":     mqttPacket(0x11, connectBody(4, 0x02, nil, "x")...),
		"varint too long":       {0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
		"varint cut":            {0x30, 0x80},
		"connect body short":    mqttPacket(0x10, 0x00),
		"connect name cut":      mqttPacket(0x10, 0x00, 0x04, 'M', 'Q'),
		"connect wrong name":    mqttPacket(0x10, 0x00, 0x04, 'H', 'T', 'T', 'P', 4, 2, 0, 60),
		"connect bad level":     mqttPacket(0x10, connectBody(9, 0x02, nil, "x")...),
		"connect reserved flag": mqttPacket(0x10, connectBody(4, 0x03, nil, "x")...),
		"http on 1883":          []byte("GET / HTTP/1.1\r\n\r\n"),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if m, ok := DecodeMQTT(frame, false); ok {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
}

func TestDecode_DispatchNewProtocols(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proto        uint8
		sport, dport uint16
		frame        []byte
		want         string
	}{
		{17, 47808, 47808, bvlc(0x0B, npdu(0x10, 0x08)...), ProtocolBACnet},
		{6, 50000, 2404, iFrame(45, 6, 1), ProtocolIEC104},
		{6, 50000, 4840, opn("None"), ProtocolOPCUA},
		{6, 50000, 1883, mqttPacket(0x10, connectBody(4, 0x02, nil, "x")...), ProtocolMQTT},
	}
	for _, tt := range tests {
		if m, ok := Decode(tt.proto, tt.sport, tt.dport, tt.frame); !ok || m.Protocol != tt.want {
			t.Errorf("%s: %+v ok=%v", tt.want, m, ok)
		}
	}
	if _, ok := Decode(6, 50000, 47808, bvlc(0x0B, npdu(0x10, 0x08)...)); ok {
		t.Error("BACnet over TCP accepted")
	}
}

func FuzzDecodeMQTT(f *testing.F) {
	f.Add(mqttPacket(0x10, connectBody(4, 0x02, nil, "s")...), false)
	f.Add(mqttPacket(0x10, connectBody(5, 0x82, []byte{0}, "s")...), false)
	f.Add(mqttPacket(0x30, 0, 1, 'a'), false)
	f.Fuzz(func(t *testing.T, p []byte, response bool) {
		if m, ok := DecodeMQTT(p, response); ok && (m.FunctionName == "" || m.Class == "") {
			t.Fatalf("bad message %+v", m)
		}
	})
}
