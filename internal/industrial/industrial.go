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
	ClassOther      Class = "other"
)

// Protocol names as they appear in the device JSON, metrics and alert rules.
const (
	ProtocolModbus = "modbus"
)

const (
	ipProtoTCP uint8 = 6
)

// Message is one decoded protocol data unit.
type Message struct {
	Protocol     string
	Function     uint8
	FunctionName string
	Class        Class
	Unit         uint8
	// Address and Quantity describe the register or coil range of a read or
	// write request; HasRange is false when the function carries none.
	Address  uint16
	Quantity uint16
	HasRange bool
	// Response is true for traffic sent by the server (the PLC or RTU).
	Response bool
	// Exception holds the exception code of an error response, 0 otherwise.
	Exception uint8
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
	return Message{}, false
}
