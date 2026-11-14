package industrial

import "encoding/binary"

// MQTTPort is the plain-text MQTT port. MQTT over TLS (8883) is encrypted
// and not decoded.
const MQTTPort = 1883

const (
	mqttConnect     = 1
	mqttConnack     = 2
	mqttPublish     = 3
	mqttPubrel      = 6
	mqttSubscribe   = 8
	mqttUnsubscribe = 10

	mqttMaxRemaining  = 268435455 // 4-byte varint maximum
	mqttFlagUsername  = 0x80
	mqttFlagReserved  = 0x01
	mqttQoSInvalid    = 3
	mqttVersion5      = 5
	mqttMaxVarintSize = 4
)

var mqttPackets = map[uint8]functionInfo{
	1:  {"connect", ClassOther},
	2:  {"connack", ClassOther},
	3:  {"publish", ClassWrite},
	4:  {"puback", ClassOther},
	5:  {"pubrec", ClassOther},
	6:  {"pubrel", ClassOther},
	7:  {"pubcomp", ClassOther},
	8:  {"subscribe", ClassRead},
	9:  {"suback", ClassOther},
	10: {"unsubscribe", ClassOther},
	11: {"unsuback", ClassOther},
	12: {"pingreq", ClassOther},
	13: {"pingresp", ClassOther},
	14: {"disconnect", ClassOther},
	15: {"auth", ClassOther},
}

// DecodeMQTT parses the fixed header and, for CONNECT and PUBLISH, the
// client id, credentials flag and topic. response is true for traffic from
// the broker.
func DecodeMQTT(p []byte, response bool) (Message, bool) {
	if len(p) < 2 {
		return Message{}, false
	}
	typ, flags := p[0]>>4, p[0]&0x0F
	f, ok := mqttPackets[typ]
	if !ok || !mqttFlagsValid(typ, flags) {
		return Message{}, false
	}
	remaining, n, ok := mqttVarint(p[1:])
	if !ok || remaining > mqttMaxRemaining {
		return Message{}, false
	}
	body := p[1+n:]
	if remaining < len(body) {
		body = body[:remaining]
	}
	m := Message{Protocol: ProtocolMQTT, Function: typ, FunctionName: f.name, Response: response, Class: ClassOther}
	if !response {
		m.Class = f.class
	}
	switch typ {
	case mqttConnect:
		if !mqttConnectInfo(body, &m) {
			return Message{}, false
		}
	case mqttConnack:
		// v3.1.1: ack flags, return code; v5: ack flags, reason code.
		if len(body) >= 2 && body[1] != 0 {
			m.Exception = body[1]
		}
	case mqttPublish:
		if len(body) >= 2 {
			tl := int(binary.BigEndian.Uint16(body[0:2]))
			if tl > 0 && 2+tl <= len(body) {
				m.Detail = "topic " + cleanString(body[2:2+tl])
			}
		}
	}
	return m, true
}

func mqttFlagsValid(typ, flags uint8) bool {
	switch typ {
	case mqttPublish:
		return (flags>>1)&0x03 != mqttQoSInvalid
	case mqttPubrel, mqttSubscribe, mqttUnsubscribe:
		return flags == 0x02
	default:
		return flags == 0
	}
}

// mqttVarint decodes the remaining-length field: value, bytes used, ok.
func mqttVarint(b []byte) (int, int, bool) {
	value, mult := 0, 1
	for i := 0; i < mqttMaxVarintSize; i++ {
		if i >= len(b) {
			return 0, 0, false
		}
		value += int(b[i]&0x7F) * mult
		if b[i]&0x80 == 0 {
			return value, i + 1, true
		}
		mult *= 128
	}
	return 0, 0, false
}

// mqttConnectInfo validates the CONNECT variable header and fills the
// client id and the no-username flag. It reports false for a malformed
// header, which also rejects non-MQTT traffic on port 1883.
func mqttConnectInfo(b []byte, m *Message) bool {
	if len(b) < 2 {
		return false
	}
	nameLen := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+nameLen+4 {
		return false
	}
	name := string(b[2 : 2+nameLen])
	if name != "MQTT" && name != "MQIsdp" {
		return false
	}
	rest := b[2+nameLen:]
	level, cflags := rest[0], rest[1]
	if level < 3 || level > 5 || cflags&mqttFlagReserved != 0 {
		return false
	}
	if cflags&mqttFlagUsername == 0 {
		m.Flag = FlagNoUsername
	}
	rest = rest[4:] // level, flags, keep alive
	if level == mqttVersion5 {
		props, n, ok := mqttVarint(rest)
		if !ok || len(rest) < n+props {
			return true
		}
		rest = rest[n+props:]
	}
	if len(rest) >= 2 {
		idLen := int(binary.BigEndian.Uint16(rest[0:2]))
		if idLen > 0 && 2+idLen <= len(rest) {
			m.Detail = "client " + cleanString(rest[2:2+idLen])
		}
	}
	return true
}
