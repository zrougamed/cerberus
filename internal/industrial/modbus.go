package industrial

import "encoding/binary"

// ModbusPort is the registered Modbus/TCP port.
const ModbusPort = 502

const (
	mbapHeaderLen = 7 // transaction id, protocol id, length, unit id
	// mbapMinLength covers the unit id and the function code. The spec caps
	// a PDU at 253 bytes, so length (unit id + PDU) is at most 254.
	mbapMinLength = 2
	mbapMaxLength = 254

	modbusExceptionBit = 0x80
	modbusMEIDeviceID  = 0x0E // MEI type for Read Device Identification
)

// Function codes from the Modbus Application Protocol v1.1b3, section 6.
const (
	fcReadCoils              = 1
	fcReadDiscreteInputs     = 2
	fcReadHoldingRegisters   = 3
	fcReadInputRegisters     = 4
	fcWriteSingleCoil        = 5
	fcWriteSingleRegister    = 6
	fcReadExceptionStatus    = 7
	fcDiagnostics            = 8
	fcGetCommEventCounter    = 11
	fcGetCommEventLog        = 12
	fcWriteMultipleCoils     = 15
	fcWriteMultipleRegisters = 16
	fcReportServerID         = 17
	fcReadFileRecord         = 20
	fcWriteFileRecord        = 21
	fcMaskWriteRegister      = 22
	fcReadWriteMultiple      = 23
	fcReadFIFOQueue          = 24
	fcEncapsulatedTransport  = 43
)

var modbusFunctions = map[uint8]functionInfo{
	fcReadCoils:              {"read_coils", ClassRead},
	fcReadDiscreteInputs:     {"read_discrete_inputs", ClassRead},
	fcReadHoldingRegisters:   {"read_holding_registers", ClassRead},
	fcReadInputRegisters:     {"read_input_registers", ClassRead},
	fcWriteSingleCoil:        {"write_single_coil", ClassWrite},
	fcWriteSingleRegister:    {"write_single_register", ClassWrite},
	fcReadExceptionStatus:    {"read_exception_status", ClassRead},
	fcDiagnostics:            {"diagnostics", ClassDiagnostic},
	fcGetCommEventCounter:    {"get_comm_event_counter", ClassRead},
	fcGetCommEventLog:        {"get_comm_event_log", ClassRead},
	fcWriteMultipleCoils:     {"write_multiple_coils", ClassWrite},
	fcWriteMultipleRegisters: {"write_multiple_registers", ClassWrite},
	fcReportServerID:         {"report_server_id", ClassRead},
	fcReadFileRecord:         {"read_file_record", ClassRead},
	fcWriteFileRecord:        {"write_file_record", ClassWrite},
	fcMaskWriteRegister:      {"mask_write_register", ClassWrite},
	fcReadWriteMultiple:      {"read_write_multiple_registers", ClassWrite},
	fcReadFIFOQueue:          {"read_fifo_queue", ClassRead},
	fcEncapsulatedTransport:  {"encapsulated_interface_transport", ClassDiagnostic},
}

// DecodeModbus parses an MBAP header and the start of the PDU. response
// says which side sent the bytes; Modbus reuses the request function code
// in the reply, so the direction cannot be told from the payload alone.
func DecodeModbus(p []byte, response bool) (Message, bool) {
	if len(p) < mbapHeaderLen+1 {
		return Message{}, false
	}
	if binary.BigEndian.Uint16(p[2:4]) != 0 {
		return Message{}, false
	}
	length := binary.BigEndian.Uint16(p[4:6])
	if length < mbapMinLength || length > mbapMaxLength {
		return Message{}, false
	}
	fc := p[7]
	if fc == 0 || fc == modbusExceptionBit {
		return Message{}, false
	}
	// Bytes of PDU data after the function code that are both declared by
	// the header and present in the capture.
	pdu := p[8:]
	if declared := int(length) - mbapMinLength; declared < len(pdu) {
		pdu = pdu[:declared]
	}

	m := Message{Protocol: ProtocolModbus, Unit: p[6], HasUnit: true, Response: response}
	if fc&modbusExceptionBit != 0 {
		fc &^= modbusExceptionBit
		m.Response = true
		if len(pdu) > 0 {
			m.Exception = pdu[0]
		}
		// The exception code may be cut off, but the high bit alone marks
		// an error reply; report something non-zero.
		if m.Exception == 0 {
			m.Exception = 0xFF
		}
	}
	m.Function = fc
	m.FunctionName, m.Class = modbusFunctionInfo(fc, pdu)
	if !m.Response {
		m.Address, m.Quantity, m.HasRange = modbusRequestRange(fc, pdu)
	}
	return m, true
}

func modbusFunctionInfo(fc uint8, pdu []byte) (string, Class) {
	if fc == fcEncapsulatedTransport && len(pdu) > 0 && pdu[0] == modbusMEIDeviceID {
		// Read Device Identification only returns vendor and model strings;
		// asset discovery tools send it constantly, so it is not a
		// diagnostic action.
		return "read_device_identification", ClassRead
	}
	if f, ok := modbusFunctions[fc]; ok {
		return f.name, f.class
	}
	return "unknown", ClassOther
}

// modbusRequestRange returns the coil/register range a request touches.
// For read/write-multiple (23) it returns the written range, since that is
// the part that changes the device.
func modbusRequestRange(fc uint8, pdu []byte) (addr, qty uint16, ok bool) {
	switch fc {
	case fcReadCoils, fcReadDiscreteInputs, fcReadHoldingRegisters, fcReadInputRegisters,
		fcWriteMultipleCoils, fcWriteMultipleRegisters:
		if len(pdu) < 4 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(pdu[0:2]), binary.BigEndian.Uint16(pdu[2:4]), true
	case fcWriteSingleCoil, fcWriteSingleRegister, fcMaskWriteRegister:
		if len(pdu) < 2 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(pdu[0:2]), 1, true
	case fcReadWriteMultiple:
		if len(pdu) < 8 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(pdu[4:6]), binary.BigEndian.Uint16(pdu[6:8]), true
	}
	return 0, 0, false
}
