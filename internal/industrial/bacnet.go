package industrial

import (
	"encoding/binary"
	"fmt"
)

// BACnetPort is the BACnet/IP UDP port (0xBAC0).
const BACnetPort = 47808

const (
	bvlcType             = 0x81
	bvlcHeaderLen        = 4
	bvlcForwardedNPDU    = 0x04
	bvlcDistributeBcast  = 0x09
	bvlcOriginalUnicast  = 0x0A
	bvlcOriginalBcast    = 0x0B
	bvlcForwardedAddrLen = 6 // original source IP + port

	npduVersion    = 0x01
	npduNetMessage = 0x80
	npduDestSpec   = 0x20
	npduSrcSpec    = 0x08

	apduConfirmed   = 0
	apduUnconfirmed = 1
	apduSimpleAck   = 2
	apduComplexAck  = 3
	apduSegmentAck  = 4
	apduError       = 5
	apduReject      = 6
	apduAbort       = 7
	apduSegmented   = 0x08

	bacnetServiceIAm  = 0
	bacnetServiceIHav = 1
	bacnetTagObjectID = 0xC4 // application tag 12, length 4
	bacnetInstMask    = 0x3FFFFF
)

// BVLC functions that do not carry an NPDU.
var bvlcFunctions = map[uint8]functionInfo{
	0x00: {"bvlc_result", ClassOther},
	0x01: {"write_broadcast_distribution_table", ClassWrite},
	0x02: {"read_broadcast_distribution_table", ClassRead},
	0x03: {"read_broadcast_distribution_table_ack", ClassOther},
	0x05: {"register_foreign_device", ClassOther},
	0x06: {"read_foreign_device_table", ClassRead},
	0x07: {"read_foreign_device_table_ack", ClassOther},
	0x08: {"delete_foreign_device_table_entry", ClassWrite},
}

// Confirmed services, ASHRAE 135 clause 21.
var bacnetConfirmed = map[uint8]functionInfo{
	0:  {"acknowledge_alarm", ClassOther},
	5:  {"subscribe_cov", ClassOther},
	6:  {"atomic_read_file", ClassRead},
	7:  {"atomic_write_file", ClassProgram},
	8:  {"add_list_element", ClassWrite},
	9:  {"remove_list_element", ClassWrite},
	10: {"create_object", ClassWrite},
	11: {"delete_object", ClassWrite},
	12: {"read_property", ClassRead},
	14: {"read_property_multiple", ClassRead},
	15: {"write_property", ClassWrite},
	16: {"write_property_multiple", ClassWrite},
	17: {"device_communication_control", ClassControl},
	18: {"confirmed_private_transfer", ClassOther},
	20: {"reinitialize_device", ClassControl},
	26: {"read_range", ClassRead},
	28: {"subscribe_cov_property", ClassOther},
}

var bacnetUnconfirmed = map[uint8]functionInfo{
	0:  {"i_am", ClassOther},
	1:  {"i_have", ClassOther},
	2:  {"unconfirmed_cov_notification", ClassOther},
	3:  {"unconfirmed_event_notification", ClassOther},
	4:  {"unconfirmed_private_transfer", ClassOther},
	5:  {"unconfirmed_text_message", ClassOther},
	6:  {"time_synchronization", ClassOther},
	7:  {"who_has", ClassOther},
	8:  {"who_is", ClassOther},
	9:  {"utc_time_synchronization", ClassOther},
	10: {"write_group", ClassWrite},
}

// DecodeBACnet parses BVLC, NPDU and the APDU type and service. I-Am
// replies yield the device instance and vendor id. BACnet/IP uses the
// same port in both directions, so direction comes from the APDU type.
func DecodeBACnet(p []byte) (Message, bool) {
	if len(p) < bvlcHeaderLen+2 || p[0] != bvlcType {
		return Message{}, false
	}
	fn := p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length < bvlcHeaderLen {
		return Message{}, false
	}
	if length < len(p) {
		p = p[:length]
	}
	m := Message{Protocol: ProtocolBACnet, Class: ClassOther}
	var npdu []byte
	switch fn {
	case bvlcOriginalUnicast, bvlcOriginalBcast, bvlcDistributeBcast:
		npdu = p[bvlcHeaderLen:]
	case bvlcForwardedNPDU:
		if len(p) < bvlcHeaderLen+bvlcForwardedAddrLen {
			return Message{}, false
		}
		npdu = p[bvlcHeaderLen+bvlcForwardedAddrLen:]
	default:
		f, ok := bvlcFunctions[fn]
		if !ok {
			return Message{}, false
		}
		m.FunctionName, m.Class = f.name, f.class
		return m, true
	}
	apdu, ok := skipNPDU(npdu)
	if !ok {
		return Message{}, false
	}
	if apdu == nil {
		m.FunctionName = "network_message"
		return m, true
	}
	return decodeAPDU(apdu, m)
}

// skipNPDU returns the APDU after the network header, nil for a network
// layer message, or ok=false when the header is malformed.
func skipNPDU(n []byte) ([]byte, bool) {
	if len(n) < 2 || n[0] != npduVersion {
		return nil, false
	}
	control := n[1]
	rest := n[2:]
	if control&npduDestSpec != 0 {
		if len(rest) < 3 || len(rest) < 3+int(rest[2]) {
			return nil, false
		}
		rest = rest[3+int(rest[2]):]
	}
	if control&npduSrcSpec != 0 {
		if len(rest) < 3 || len(rest) < 3+int(rest[2]) {
			return nil, false
		}
		rest = rest[3+int(rest[2]):]
	}
	if control&npduDestSpec != 0 {
		if len(rest) < 1 {
			return nil, false
		}
		rest = rest[1:] // hop count
	}
	if control&npduNetMessage != 0 {
		return nil, true
	}
	if len(rest) == 0 {
		return nil, false
	}
	return rest, true
}

func decodeAPDU(a []byte, m Message) (Message, bool) {
	typ := a[0] >> 4
	var svcIdx int
	var table map[uint8]functionInfo
	switch typ {
	case apduConfirmed:
		svcIdx, table = 3, bacnetConfirmed
		if a[0]&apduSegmented != 0 {
			svcIdx = 5
		}
	case apduUnconfirmed:
		svcIdx, table = 1, bacnetUnconfirmed
	case apduSimpleAck, apduError:
		svcIdx, table, m.Response = 2, bacnetConfirmed, true
	case apduComplexAck:
		svcIdx, table, m.Response = 2, bacnetConfirmed, true
		if a[0]&apduSegmented != 0 {
			svcIdx = 4
		}
	case apduSegmentAck, apduReject, apduAbort:
		m.Response = true
		m.FunctionName = map[uint8]string{apduSegmentAck: "segment_ack", apduReject: "reject", apduAbort: "abort"}[typ]
		if typ != apduSegmentAck {
			m.Exception = 1
		}
		return m, true
	default:
		return Message{}, false
	}
	if len(a) <= svcIdx {
		return Message{}, false
	}
	svc := a[svcIdx]
	f, ok := table[svc]
	if !ok {
		f = functionInfo{fmt.Sprintf("service_%d", svc), ClassOther}
	}
	m.Function, m.FunctionName = svc, f.name
	if !m.Response {
		m.Class = f.class
	}
	if typ == apduError {
		m.Exception = 1
	}
	if typ == apduUnconfirmed && (svc == bacnetServiceIAm || svc == bacnetServiceIHav) {
		// The device is announcing itself: it is the server side.
		m.Response = true
		m.Class = ClassOther
		if svc == bacnetServiceIAm {
			m.Identity, m.Detail = parseIAm(a[svcIdx+1:])
		}
	}
	return m, true
}

// parseIAm reads the device object identifier and vendor id from an I-Am:
// object-id, max-APDU (unsigned), segmentation (enumerated), vendor-id.
func parseIAm(b []byte) (*Identity, string) {
	if len(b) < 5 || b[0] != bacnetTagObjectID {
		return nil, ""
	}
	instance := binary.BigEndian.Uint32(b[1:5]) & bacnetInstMask
	detail := fmt.Sprintf("device %d", instance)
	id := &Identity{Model: detail, DeviceType: "BACnet device"}
	rest := b[5:]
	for range 2 { // skip max-APDU and segmentation
		if len(rest) < 1 || len(rest) < 1+int(rest[0]&0x07) {
			return id, detail
		}
		rest = rest[1+int(rest[0]&0x07):]
	}
	if len(rest) < 2 || rest[0]>>4 != 2 { // application tag 2: unsigned
		return id, detail
	}
	n := int(rest[0] & 0x07)
	if n < 1 || n > 2 || len(rest) < 1+n {
		return id, detail
	}
	vendor := uint16(rest[1])
	if n == 2 {
		vendor = binary.BigEndian.Uint16(rest[1:3])
	}
	id.Vendor = fmt.Sprintf("BACnet vendor %d", vendor)
	return id, detail
}
