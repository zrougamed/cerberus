package industrial

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// S7Port is ISO-on-TCP (RFC 1006), which carries S7comm. IEC 61850 MMS
// uses the same port and framing, so the decoder checks for S7 markers
// before claiming a packet.
const S7Port = 102

const (
	tpktVersion   = 3
	tpktHeaderLen = 4

	cotpTypeCR = 0xE0 // connection request
	cotpTypeCC = 0xD0 // connection confirm
	cotpTypeDT = 0xF0 // data
	cotpDTLen  = 2    // length byte value of a DT header: type + TPDU number
	// Fixed part of a CR/CC after the length byte: type, dst ref, src ref,
	// class. Parameters follow.
	cotpConnFixedLen = 6
	cotpParamSrcTSAP = 0xC1
	cotpParamDstTSAP = 0xC2

	s7ProtocolID     = 0x32
	s7PlusProtocolID = 0x72
	s7HeaderLen      = 10 // protocol id, ROSCTR, reserved, PDU ref, param len, data len
	s7AckHeaderLen   = 12 // plus error class and error code

	s7RosctrJob      = 1
	s7RosctrAck      = 2
	s7RosctrAckData  = 3
	s7RosctrUserdata = 7

	s7FuncPIService = 0x28
	// A PI service parameter starts with the function code and 7 bytes the
	// spec leaves unnamed, then a 2-byte block length.
	s7PIFixedLen = 8
)

// Job functions, from the S7comm dissector in Wireshark (packet-s7comm.c).
var s7Functions = map[uint8]functionInfo{
	0x00:            {"cpu_services", ClassOther},
	0xF0:            {"setup_communication", ClassOther},
	0x04:            {"read_var", ClassRead},
	0x05:            {"write_var", ClassWrite},
	0x1A:            {"request_download", ClassProgram},
	0x1B:            {"download_block", ClassProgram},
	0x1C:            {"download_ended", ClassProgram},
	0x1D:            {"start_upload", ClassRead},
	0x1E:            {"upload", ClassRead},
	0x1F:            {"end_upload", ClassRead},
	s7FuncPIService: {"pi_service", ClassControl},
	0x29:            {"plc_stop", ClassControl},
}

// PI (program invocation) service names and what they do.
var s7PIServices = map[string]functionInfo{
	"P_PROGRAM": {"plc_start", ClassControl},
	"_DELE":     {"delete_block", ClassProgram},
	"_INSE":     {"insert_block", ClassProgram},
	"_GARB":     {"compress_memory", ClassProgram},
	"_MODU":     {"copy_ram_to_rom", ClassProgram},
}

// DecodeS7 parses TPKT and COTP and, for data TPDUs, the S7comm header and
// function. COTP connection requests are reported with the rack and slot
// taken from the destination TSAP. response is the port-based direction;
// for S7 jobs and acks the header itself says which side sent it.
func DecodeS7(p []byte, response bool) (Message, bool) {
	if len(p) < tpktHeaderLen+3 || p[0] != tpktVersion || p[1] != 0 {
		return Message{}, false
	}
	tpktLen := int(binary.BigEndian.Uint16(p[2:4]))
	cotpLen := int(p[4])
	if tpktLen < tpktHeaderLen+1+cotpLen || cotpLen < cotpDTLen {
		return Message{}, false
	}
	// Bytes declared by TPKT and present in the capture.
	if tpktLen < len(p) {
		p = p[:tpktLen]
	}
	cotp := p[tpktHeaderLen+1:]
	if len(cotp) < cotpLen {
		return Message{}, false
	}
	switch cotp[0] {
	case cotpTypeCR, cotpTypeCC:
		return decodeCOTPConnect(cotp[:cotpLen], cotp[0] == cotpTypeCC)
	case cotpTypeDT:
		if cotpLen != cotpDTLen {
			return Message{}, false
		}
		return decodeS7PDU(cotp[cotpLen:], response)
	}
	return Message{}, false
}

func decodeCOTPConnect(c []byte, confirm bool) (Message, bool) {
	if len(c) < cotpConnFixedLen {
		return Message{}, false
	}
	var dstTSAP []byte
	for params := c[cotpConnFixedLen:]; len(params) >= 2; {
		code, n := params[0], int(params[1])
		if len(params) < 2+n {
			return Message{}, false
		}
		if code == cotpParamDstTSAP {
			dstTSAP = params[2 : 2+n]
		}
		params = params[2+n:]
	}
	// S7 TSAPs are two bytes: connection type (1 PG, 2 OP, 3 S7 basic)
	// and rack/slot. MMS and other ISO users pick different values, so
	// anything else is not claimed.
	if len(dstTSAP) != 2 || dstTSAP[0] < 1 || dstTSAP[0] > 3 {
		return Message{}, false
	}
	m := Message{
		Protocol:     ProtocolS7,
		FunctionName: "cotp_connect",
		Class:        ClassOther,
		Response:     confirm,
		Detail:       fmt.Sprintf("rack %d slot %d", dstTSAP[1]>>5, dstTSAP[1]&0x1F),
	}
	if confirm {
		m.FunctionName = "cotp_connect_confirm"
	}
	return m, true
}

func decodeS7PDU(s []byte, response bool) (Message, bool) {
	if len(s) < 2 {
		return Message{}, false
	}
	if s[0] == s7PlusProtocolID {
		// S7comm-plus: byte 1 is the protocol version (1, 2 or 3).
		if s[1] < 1 || s[1] > 3 {
			return Message{}, false
		}
		return Message{Protocol: ProtocolS7Plus, FunctionName: "s7comm_plus", Class: ClassOther, Response: response}, true
	}
	if s[0] != s7ProtocolID || len(s) < s7HeaderLen || s[2] != 0 || s[3] != 0 {
		return Message{}, false
	}
	m := Message{Protocol: ProtocolS7}
	hdr := s7HeaderLen
	switch s[1] {
	case s7RosctrJob:
		m.Response = false
	case s7RosctrAck, s7RosctrAckData:
		m.Response = true
		hdr = s7AckHeaderLen
		if len(s) < hdr {
			return Message{}, false
		}
		m.Exception = s[10] // error class; 0 means success
	case s7RosctrUserdata:
		// Userdata (SZL reads, block info, clock, security) goes both ways
		// and is decoded by the asset work, not here.
		m.Response = response
		m.FunctionName, m.Class = "userdata", ClassOther
		return m, true
	default:
		return Message{}, false
	}

	paramLen := int(binary.BigEndian.Uint16(s[6:8]))
	params := s[hdr:]
	if paramLen < len(params) {
		params = params[:paramLen]
	}
	if len(params) == 0 {
		// An Ack without parameters, or a job whose parameters were cut.
		m.FunctionName, m.Class = "ack", ClassOther
		if !m.Response {
			return Message{}, false
		}
		return m, true
	}
	m.Function = params[0]
	f, ok := s7Functions[m.Function]
	if !ok {
		m.FunctionName, m.Class = "unknown", ClassOther
		return m, true
	}
	m.FunctionName, m.Class = f.name, f.class
	if m.Function == s7FuncPIService && !m.Response {
		if pi, ok := s7PIService(params); ok {
			m.FunctionName, m.Class = pi.name, pi.class
		}
	}
	return m, true
}

func s7PIService(params []byte) (functionInfo, bool) {
	if len(params) < s7PIFixedLen+2 {
		return functionInfo{}, false
	}
	blockLen := int(binary.BigEndian.Uint16(params[s7PIFixedLen : s7PIFixedLen+2]))
	rest := params[s7PIFixedLen+2:]
	if len(rest) < blockLen+1 {
		return functionInfo{}, false
	}
	rest = rest[blockLen:]
	nameLen := int(rest[0])
	if len(rest) < 1+nameLen {
		return functionInfo{}, false
	}
	pi, ok := s7PIServices[string(bytes.TrimRight(rest[1:1+nameLen], "\x00"))]
	return pi, ok
}
