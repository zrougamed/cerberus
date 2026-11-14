package industrial

import (
	"encoding/binary"
	"fmt"
)

// DNP3Port is the registered DNP3 port, used over both TCP and UDP.
const DNP3Port = 20000

const (
	dnp3Start0       = 0x05
	dnp3Start1       = 0x64
	dnp3LinkHdrLen   = 10 // start(2) length control dest(2) src(2) crc(2)
	dnp3MinLength    = 5  // control + dest + src
	dnp3LinkPRM      = 0x40
	dnp3LinkUserData = 0x03 // confirmed user data
	dnp3LinkUnconf   = 0x04 // unconfirmed user data

	dnp3FuncResponse     = 129
	dnp3FuncUnsolicited  = 130
	dnp3FuncAuthResponse = 131

	// Low three IIN2 bits: function not supported, object unknown,
	// parameter error. Any of them makes the response an error reply.
	dnp3IIN2ErrorMask = 0x07
)

// Application function codes, IEEE 1815-2012 table 4-1.
var dnp3Functions = map[uint8]functionInfo{
	0:  {"confirm", ClassOther},
	1:  {"read", ClassRead},
	2:  {"write", ClassWrite},
	3:  {"select", ClassControl},
	4:  {"operate", ClassControl},
	5:  {"direct_operate", ClassControl},
	6:  {"direct_operate_no_ack", ClassControl},
	7:  {"immediate_freeze", ClassOther},
	8:  {"immediate_freeze_no_ack", ClassOther},
	9:  {"freeze_clear", ClassWrite},
	10: {"freeze_clear_no_ack", ClassWrite},
	11: {"freeze_at_time", ClassOther},
	12: {"freeze_at_time_no_ack", ClassOther},
	13: {"cold_restart", ClassDiagnostic},
	14: {"warm_restart", ClassDiagnostic},
	15: {"initialize_data", ClassDiagnostic},
	16: {"initialize_application", ClassDiagnostic},
	17: {"start_application", ClassControl},
	18: {"stop_application", ClassControl},
	19: {"save_configuration", ClassDiagnostic},
	20: {"enable_unsolicited", ClassOther},
	21: {"disable_unsolicited", ClassDiagnostic},
	22: {"assign_class", ClassOther},
	23: {"delay_measure", ClassOther},
	24: {"record_current_time", ClassOther},
	25: {"open_file", ClassOther},
	26: {"close_file", ClassOther},
	27: {"delete_file", ClassProgram},
	28: {"get_file_info", ClassRead},
	29: {"authenticate_file", ClassOther},
	30: {"abort_file", ClassOther},
	31: {"activate_config", ClassProgram},
	32: {"authenticate_request", ClassOther},
	33: {"authenticate_request_no_ack", ClassOther},

	dnp3FuncResponse:     {"response", ClassOther},
	dnp3FuncUnsolicited:  {"unsolicited_response", ClassOther},
	dnp3FuncAuthResponse: {"authenticate_response", ClassOther},
}

// DecodeDNP3 validates the link header (start bytes, length, CRC) and reads
// the transport and application headers from the first data block. Link
// frames without user data are reported as "link_layer".
func DecodeDNP3(p []byte) (Message, bool) {
	if len(p) < dnp3LinkHdrLen || p[0] != dnp3Start0 || p[1] != dnp3Start1 {
		return Message{}, false
	}
	length := p[2]
	if length < dnp3MinLength {
		return Message{}, false
	}
	if dnp3CRC(p[:8]) != binary.LittleEndian.Uint16(p[8:10]) {
		return Message{}, false
	}
	control := p[3]
	dest := binary.LittleEndian.Uint16(p[4:6])
	src := binary.LittleEndian.Uint16(p[6:8])
	linkFunc := control & 0x0F
	userData := control&dnp3LinkPRM != 0 && (linkFunc == dnp3LinkUserData || linkFunc == dnp3LinkUnconf)

	m := Message{Protocol: ProtocolDNP3}
	if !userData || length == dnp3MinLength {
		m.FunctionName, m.Class = "link_layer", ClassOther
		return m, true
	}
	// First data block: transport header, application control, function.
	if len(p) < dnp3LinkHdrLen+3 {
		return Message{}, false
	}
	fc := p[dnp3LinkHdrLen+2]
	f, ok := dnp3Functions[fc]
	if !ok {
		f = functionInfo{"unknown", ClassOther}
	}
	m.Function, m.FunctionName, m.Class = fc, f.name, f.class
	m.Response = fc >= dnp3FuncResponse
	outstation := dest
	if m.Response {
		outstation = src
		if len(p) >= dnp3LinkHdrLen+5 && fc != dnp3FuncAuthResponse {
			if iin2 := p[dnp3LinkHdrLen+4] & dnp3IIN2ErrorMask; iin2 != 0 {
				m.Exception = iin2
			}
		}
	}
	m.Detail = fmt.Sprintf("outstation %d", outstation)
	return m, true
}

// dnp3CRC is the DNP3 link-layer CRC: polynomial 0x3D65, reflected, final
// value inverted.
func dnp3CRC(b []byte) uint16 {
	var crc uint16
	for _, c := range b {
		crc ^= uint16(c)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
