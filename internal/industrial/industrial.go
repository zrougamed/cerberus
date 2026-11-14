// Package industrial decodes industrial control protocols from the first
// bytes of a TCP or UDP payload.
//
// The TC program copies at most models.L7PayloadSize bytes per packet and
// zero-pads the rest, and it does not report the real payload length. Every
// decoder therefore validates header fields against each other before
// trusting them, and treats an all-zero buffer (a bare ACK) as "not this
// protocol" rather than as a message with function code 0.
package industrial

// Class groups function codes by what they do to the device, which is what
// alerting and baselining care about. The exact function is kept in
// Message.FunctionName.
type Class string

const (
	ClassRead       Class = "read"
	ClassWrite      Class = "write"
	ClassDiagnostic Class = "diagnostic"
	// ClassControl changes the run state of a controller (start, stop).
	ClassControl Class = "control"
	// ClassProgram changes the logic on a controller (download, delete).
	ClassProgram Class = "program"
	ClassOther   Class = "other"
)

// Protocol names as they appear in the device JSON, metrics and alert rules.
const (
	ProtocolModbus = "modbus"
	ProtocolS7     = "s7comm"
	// ProtocolS7Plus is the newer, integrity-protected S7 protocol. It is
	// only detected and counted, not decoded.
	ProtocolS7Plus = "s7comm_plus"
	ProtocolDNP3   = "dnp3"
)

const (
	ipProtoTCP uint8 = 6
	ipProtoUDP uint8 = 17
)

// functionInfo is a function code's name and class in a decoder table.
type functionInfo struct {
	name  string
	class Class
}

// Message is one decoded protocol data unit.
type Message struct {
	Protocol     string
	Function     uint8
	FunctionName string
	Class        Class
	// Unit is the Modbus unit id; HasUnit is false for protocols without one.
	Unit    uint8
	HasUnit bool
	// Address and Quantity describe the register or coil range of a read or
	// write request; HasRange is false when the function carries none.
	Address  uint16
	Quantity uint16
	HasRange bool
	// Response is true for traffic sent by the server (the PLC or RTU).
	Response bool
	// Exception holds the exception code of an error response, 0 otherwise.
	Exception uint8
	// Detail is a short protocol-specific note worth counting, such as the
	// S7 rack and slot a client connects to. Empty when there is none.
	Detail string
}

// Decode picks a decoder from the transport and ports and runs it on
// payload. ok is false when no decoder applies or the bytes do not form a
// valid header for the protocol on that port.
func Decode(ipProto uint8, srcPort, dstPort uint16, payload []byte) (Message, bool) {
	if ipProto == ipProtoTCP && (dstPort == ModbusPort || srcPort == ModbusPort) {
		// Traffic from 502 to 502 is unusual; treat it as a request so a
		// write is never mistaken for a harmless reply.
		response := srcPort == ModbusPort && dstPort != ModbusPort
		return DecodeModbus(payload, response)
	}
	if ipProto == ipProtoTCP && (dstPort == S7Port || srcPort == S7Port) {
		return DecodeS7(payload, srcPort == S7Port && dstPort != S7Port)
	}
	if (ipProto == ipProtoTCP || ipProto == ipProtoUDP) && (dstPort == DNP3Port || srcPort == DNP3Port) {
		// DNP3 carries its own direction in the function code.
		return DecodeDNP3(payload)
	}
	return Message{}, false
}
