package industrial

import (
	"encoding/binary"
	"strings"
)

// OPCUAPort is the registered OPC UA binary (opc.tcp) port.
const OPCUAPort = 4840

const (
	opcuaHeaderLen = 8 // message type(3), chunk type(1), size(4)
	// Secure channel id, token id, sequence number, request id.
	opcuaMsgPrefixLen = 16
	// Largest chunk we accept as plausible; the spec lets peers negotiate
	// buffer sizes, real deployments stay far below this.
	opcuaMaxChunk = 16 << 20

	nodeIDTwoByte  = 0x00
	nodeIDFourByte = 0x01
	nodeIDNumeric  = 0x02

	opcuaPolicyNone = "None"
)

var opcuaMessageTypes = map[string]string{
	"HEL": "hello",
	"ACK": "acknowledge",
	"ERR": "error",
	"OPN": "open_secure_channel",
	"MSG": "message",
	"CLO": "close_secure_channel",
	"RHE": "reverse_hello",
}

// Service request/response type ids (binary encoding ids, namespace 0).
var opcuaServices = map[uint32]functionInfo{
	461: {"create_session", ClassOther},
	464: {"create_session_response", ClassOther},
	467: {"activate_session", ClassOther},
	470: {"activate_session_response", ClassOther},
	473: {"close_session", ClassOther},
	476: {"close_session_response", ClassOther},
	527: {"browse", ClassRead},
	530: {"browse_response", ClassOther},
	631: {"read", ClassRead},
	634: {"read_response", ClassOther},
	673: {"write", ClassWrite},
	676: {"write_response", ClassOther},
	712: {"call", ClassControl},
	715: {"call_response", ClassOther},
	787: {"create_subscription", ClassOther},
	790: {"create_subscription_response", ClassOther},
	826: {"publish", ClassOther},
	829: {"publish_response", ClassOther},
}

// DecodeOPCUA parses the OPC UA binary message header. For OPN it reads the
// security policy, which is sent in the clear; for MSG it reads the
// service type id, which is only readable when the channel is not
// encrypted (an encrypted body does not match a known id and stays
// "message").
func DecodeOPCUA(p []byte, response bool) (Message, bool) {
	if len(p) < opcuaHeaderLen {
		return Message{}, false
	}
	name, ok := opcuaMessageTypes[string(p[0:3])]
	if !ok || (p[3] != 'F' && p[3] != 'C' && p[3] != 'A') {
		return Message{}, false
	}
	size := binary.LittleEndian.Uint32(p[4:8])
	if size < opcuaHeaderLen || size > opcuaMaxChunk {
		return Message{}, false
	}
	if int(size) < len(p) {
		p = p[:size]
	}
	m := Message{Protocol: ProtocolOPCUA, FunctionName: name, Class: ClassOther, Response: response}
	body := p[opcuaHeaderLen:]
	switch string(p[0:3]) {
	case "OPN":
		if policy, ok := opcuaPolicy(body); ok {
			m.Detail = "security policy " + policy
			if policy == opcuaPolicyNone && !response {
				m.Flag = FlagInsecurePolicy
			}
		}
	case "MSG":
		if id, ok := opcuaTypeID(body); ok {
			if f, known := opcuaServices[id]; known {
				m.Function = uint8(min(id, 0xFF))
				m.FunctionName = f.name
				if !response {
					m.Class = f.class
				}
			}
		}
	case "ERR":
		m.Exception = 1
	}
	return m, true
}

// opcuaPolicy reads the security policy URI from an OPN body: secure
// channel id(4), URI length(4, signed), URI. Returns the part after '#'.
func opcuaPolicy(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	// The length is a signed int32 where -1 means null; read unsigned, a
	// negative value is then larger than any capture and fails the check.
	n := int64(binary.LittleEndian.Uint32(b[4:8]))
	rest := b[8:]
	if n == 0 || n > int64(len(rest)) {
		return "", false
	}
	uri := string(rest[:n])
	_, policy, found := strings.Cut(uri, "#")
	if !found || policy == "" {
		return "", false
	}
	return cleanString([]byte(policy)), true
}

// opcuaTypeID reads the NodeId that names the service in a MSG body.
func opcuaTypeID(b []byte) (uint32, bool) {
	if len(b) < opcuaMsgPrefixLen+2 {
		return 0, false
	}
	n := b[opcuaMsgPrefixLen:]
	switch n[0] {
	case nodeIDTwoByte:
		return uint32(n[1]), true
	case nodeIDFourByte:
		if len(n) < 4 || n[1] != 0 {
			return 0, false
		}
		return uint32(binary.LittleEndian.Uint16(n[2:4])), true
	case nodeIDNumeric:
		if len(n) < 7 || binary.LittleEndian.Uint16(n[1:3]) != 0 {
			return 0, false
		}
		return binary.LittleEndian.Uint32(n[3:7]), true
	}
	return 0, false
}
