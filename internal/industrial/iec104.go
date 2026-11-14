package industrial

import (
	"encoding/binary"
	"fmt"
)

// IEC104Port is the IEC 60870-5-104 port.
const IEC104Port = 2404

const (
	iec104Start     = 0x68
	iec104MinLength = 4   // control fields only (S and U frames)
	iec104MaxLength = 253 // APDU length cap from the standard
	iec104ASDUStart = 6   // start byte, length, 4 control bytes
	iec104ASDUHdr   = 6   // type, VSQ, COT(2), common address(2)

	iec104CauseMask     = 0x3F
	iec104CauseNegative = 0x40
	iec104CauseRequest  = 5 // request or requested
	iec104CauseActivate = 6
	iec104CauseDeact    = 8

	iec104LastMonitorType = 44
)

var iec104UFrames = map[uint8]struct {
	name     string
	response bool
}{
	0x07: {"startdt_act", false},
	0x0B: {"startdt_con", true},
	0x13: {"stopdt_act", false},
	0x23: {"stopdt_con", true},
	0x43: {"testfr_act", false},
	0x83: {"testfr_con", true},
}

// Control and system type ids, IEC 60870-5-101/104 section 7.2.1.
var iec104Types = map[uint8]functionInfo{
	45:  {"single_command", ClassControl},
	46:  {"double_command", ClassControl},
	47:  {"regulating_step_command", ClassControl},
	48:  {"setpoint_normalized", ClassControl},
	49:  {"setpoint_scaled", ClassControl},
	50:  {"setpoint_float", ClassControl},
	51:  {"bitstring_command", ClassControl},
	58:  {"single_command_time", ClassControl},
	59:  {"double_command_time", ClassControl},
	60:  {"regulating_step_command_time", ClassControl},
	61:  {"setpoint_normalized_time", ClassControl},
	62:  {"setpoint_scaled_time", ClassControl},
	63:  {"setpoint_float_time", ClassControl},
	64:  {"bitstring_command_time", ClassControl},
	70:  {"end_of_initialization", ClassOther},
	100: {"interrogation", ClassRead},
	101: {"counter_interrogation", ClassRead},
	102: {"read", ClassRead},
	103: {"clock_sync", ClassOther},
	104: {"test", ClassOther},
	105: {"reset_process", ClassDiagnostic},
	106: {"delay_acquisition", ClassOther},
	107: {"test_time", ClassOther},
	110: {"parameter_normalized", ClassWrite},
	111: {"parameter_scaled", ClassWrite},
	112: {"parameter_float", ClassWrite},
	113: {"parameter_activation", ClassWrite},
}

// DecodeIEC104 parses the APCI and, for I-frames, the ASDU header. The
// cause of transmission says whether an ASDU is a command (activation,
// deactivation, request) or a reply; monitoring types are always replies.
func DecodeIEC104(p []byte) (Message, bool) {
	if len(p) < iec104ASDUStart || p[0] != iec104Start {
		return Message{}, false
	}
	length := int(p[1])
	if length < iec104MinLength || length > iec104MaxLength {
		return Message{}, false
	}
	m := Message{Protocol: ProtocolIEC104, Class: ClassOther}
	c1, c2, c3 := p[2], p[3], p[4]
	switch {
	case c1&0x01 == 0: // I-frame
		if length < iec104MinLength+iec104ASDUHdr || len(p) < iec104ASDUStart+iec104ASDUHdr || c3&0x01 != 0 {
			return Message{}, false
		}
	case c1&0x03 == 0x01: // S-frame
		if c1 != 0x01 || c2 != 0 || c3&0x01 != 0 || length != iec104MinLength {
			return Message{}, false
		}
		m.FunctionName = "s_frame"
		return m, true
	default: // U-frame
		u, ok := iec104UFrames[c1]
		if !ok || c2 != 0 || c3 != 0 || length != iec104MinLength {
			return Message{}, false
		}
		m.FunctionName, m.Response = u.name, u.response
		return m, true
	}

	asdu := p[iec104ASDUStart:]
	typ := asdu[0]
	cause := asdu[2] & iec104CauseMask
	if typ == 0 || cause == 0 {
		return Message{}, false
	}
	m.Function = typ
	m.Detail = fmt.Sprintf("common address %d", binary.LittleEndian.Uint16(asdu[4:6]))
	if asdu[2]&iec104CauseNegative != 0 {
		m.Exception = cause
	}
	if typ <= iec104LastMonitorType {
		m.FunctionName, m.Response = "monitor_data", true
		return m, true
	}
	f, ok := iec104Types[typ]
	if !ok {
		f = functionInfo{fmt.Sprintf("type_%d", typ), ClassOther}
	}
	m.FunctionName = f.name
	m.Response = cause != iec104CauseActivate && cause != iec104CauseDeact && cause != iec104CauseRequest
	if !m.Response {
		m.Class = f.class
	}
	return m, true
}
