package industrial

import (
	"encoding/binary"
	"fmt"
)

// ENIPPort is the EtherNet/IP explicit messaging port (TCP and UDP).
// Implicit I/O on UDP 2222 is not decoded.
const ENIPPort = 44818

const (
	enipHeaderLen = 24 // command, length, session, status, context(8), options
	enipMaxLength = 65511

	enipListServices   = 0x0004
	enipListIdentity   = 0x0063
	enipListInterfaces = 0x0064
	enipRegister       = 0x0065
	enipUnregister     = 0x0066
	enipSendRRData     = 0x006F
	enipSendUnitData   = 0x0070
	enipIndicateStatus = 0x0072
	enipCancel         = 0x0073

	cpfItemUnconnected = 0x00B2
	cpfItemConnected   = 0x00B1
	cpfItemIdentity    = 0x000C
	// SendRRData/SendUnitData: interface handle(4) + timeout(2) + item count(2).
	cpfPrefixLen = 8

	cipResponseBit        = 0x80
	cipClassConnectionMgr = 0x06
	cipServiceUnconnSend  = 0x52
	// Unconnected Send data before the embedded request: priority/tick,
	// timeout ticks, embedded message size.
	cipUnconnSendHdrLen = 4

	// ListIdentity reply item layout, offsets from the start of the item
	// data: encapsulation version(2), socket address(16), then identity.
	lidVendor   = 18
	lidType     = 20
	lidRevision = 24
	lidSerial   = 28
	lidName     = 32
)

var enipCommands = map[uint16]string{
	enipListServices:   "list_services",
	enipListIdentity:   "list_identity",
	enipListInterfaces: "list_interfaces",
	enipRegister:       "register_session",
	enipUnregister:     "unregister_session",
	enipSendRRData:     "send_rr_data",
	enipSendUnitData:   "send_unit_data",
	enipIndicateStatus: "indicate_status",
	enipCancel:         "cancel",
}

// Common CIP services, CIP Vol. 1 appendix A.
var cipServices = map[uint8]functionInfo{
	0x01: {"get_attributes_all", ClassRead},
	0x02: {"set_attributes_all", ClassWrite},
	0x03: {"get_attribute_list", ClassRead},
	0x04: {"set_attribute_list", ClassWrite},
	0x05: {"reset", ClassControl},
	0x06: {"start", ClassControl},
	0x07: {"stop", ClassControl},
	0x08: {"create", ClassWrite},
	0x09: {"delete", ClassWrite},
	0x0A: {"multiple_service_packet", ClassOther},
	0x0D: {"apply_attributes", ClassWrite},
	0x0E: {"get_attribute_single", ClassRead},
	0x10: {"set_attribute_single", ClassWrite},
	0x11: {"find_next_object_instance", ClassRead},
	0x15: {"restore", ClassWrite},
	0x16: {"save", ClassOther},
	0x18: {"get_member", ClassRead},
	0x19: {"set_member", ClassWrite},
}

// Connection Manager (class 6) services.
var cipConnectionMgrServices = map[uint8]functionInfo{
	0x4E: {"forward_close", ClassOther},
	0x52: {"unconnected_send", ClassOther},
	0x54: {"forward_open", ClassOther},
	0x5B: {"large_forward_open", ClassOther},
}

// Logix controller tag services; class-specific codes used on symbol and
// template objects and with symbolic paths.
var cipLogixServices = map[uint8]functionInfo{
	0x4C: {"read_tag", ClassRead},
	0x4D: {"write_tag", ClassWrite},
	0x4E: {"read_modify_write_tag", ClassWrite},
	0x52: {"read_tag_fragmented", ClassRead},
	0x53: {"write_tag_fragmented", ClassWrite},
	0x55: {"get_instance_attribute_list", ClassRead},
}

var cipVendors = map[uint16]string{
	1: "Rockwell Automation",
}

var cipDeviceTypes = map[uint16]string{
	0x02: "AC drive",
	0x07: "discrete I/O",
	0x0C: "communications adapter",
	0x0E: "programmable logic controller",
	0x18: "human-machine interface",
}

// DecodeENIP parses the encapsulation header and, for SendRRData and
// SendUnitData, the CIP service inside. ListIdentity replies yield an
// Identity. response is the port-based direction.
func DecodeENIP(p []byte, response bool) (Message, bool) {
	if len(p) < enipHeaderLen {
		return Message{}, false
	}
	cmd := binary.LittleEndian.Uint16(p[0:2])
	length := int(binary.LittleEndian.Uint16(p[2:4]))
	status := binary.LittleEndian.Uint32(p[8:12])
	name, ok := enipCommands[cmd]
	if !ok || length > enipMaxLength || binary.LittleEndian.Uint32(p[20:24]) != 0 {
		return Message{}, false
	}
	// Requests always carry status 0.
	if !response && status != 0 {
		return Message{}, false
	}
	m := Message{Protocol: ProtocolENIP, FunctionName: name, Class: ClassOther, Response: response}
	if status != 0 {
		m.Exception = uint8(min(status, 0xFF))
	}
	body := p[enipHeaderLen:]
	if length < len(body) {
		body = body[:length]
	}
	switch cmd {
	case enipListIdentity:
		if response {
			m.Identity = parseListIdentity(body)
		}
	case enipSendRRData, enipSendUnitData:
		decodeCPF(body, &m)
	}
	return m, true
}

// decodeCPF walks the common packet format items and decodes the CIP
// message in the data item, if it is in the capture.
func decodeCPF(b []byte, m *Message) {
	if len(b) < cpfPrefixLen {
		return
	}
	count := int(binary.LittleEndian.Uint16(b[6:8]))
	items := b[cpfPrefixLen:]
	for range count {
		if len(items) < 4 {
			return
		}
		typ := binary.LittleEndian.Uint16(items[0:2])
		n := int(binary.LittleEndian.Uint16(items[2:4]))
		data := items[4:]
		if n < len(data) {
			data = data[:n]
		}
		switch typ {
		case cpfItemUnconnected:
			decodeCIP(data, m, true)
			return
		case cpfItemConnected:
			if len(data) > 2 { // sequence count first
				decodeCIP(data[2:], m, true)
			}
			return
		}
		if len(items) < 4+n {
			return
		}
		items = items[4+n:]
	}
}

// decodeCIP reads a CIP request or response. nest allows one level of
// Unconnected Send, which is how engineering tools reach a controller
// through a communications module.
func decodeCIP(b []byte, m *Message, nest bool) {
	if len(b) < 2 {
		return
	}
	service := b[0]
	if service&cipResponseBit != 0 {
		m.Response = true
		service &^= cipResponseBit
		if len(b) >= 3 && b[2] != 0 {
			m.Exception = b[2] // general status
		}
		// Replies carry no path, so the class is unknown; the tag services
		// are the ones worth naming.
		f, ok := cipServices[service]
		if !ok {
			f, ok = cipLogixServices[service]
		}
		if ok {
			m.Function, m.FunctionName, m.Class = service, f.name, f.class
		}
		return
	}
	pathLen := int(b[1]) * 2
	if len(b) < 2+pathLen {
		return
	}
	class := cipPathClass(b[2 : 2+pathLen])
	var f functionInfo
	var ok bool
	switch {
	case class == cipClassConnectionMgr:
		f, ok = cipConnectionMgrServices[service]
	case service < 0x4B:
		f, ok = cipServices[service]
	default:
		f, ok = cipLogixServices[service]
	}
	if !ok {
		f = functionInfo{fmt.Sprintf("service_0x%02x", service), ClassOther}
	}
	m.Function, m.FunctionName, m.Class = service, f.name, f.class
	if nest && class == cipClassConnectionMgr && service == cipServiceUnconnSend {
		rest := b[2+pathLen:]
		if len(rest) > cipUnconnSendHdrLen {
			decodeCIP(rest[cipUnconnSendHdrLen:], m, false)
		}
	}
}

// cipPathClass returns the class id from an EPATH, or 0 when the path has
// no class segment (symbolic tag paths).
func cipPathClass(path []byte) uint16 {
	for len(path) >= 2 {
		switch path[0] {
		case 0x20: // 8-bit class
			return uint16(path[1])
		case 0x21: // 16-bit class, after a pad byte
			if len(path) < 4 {
				return 0
			}
			return binary.LittleEndian.Uint16(path[2:4])
		case 0x24, 0x30: // 8-bit instance, attribute
			path = path[2:]
		case 0x25, 0x31: // 16-bit instance, attribute
			if len(path) < 4 {
				return 0
			}
			path = path[4:]
		default:
			return 0
		}
	}
	return 0
}

// parseListIdentity reads the first identity item of a ListIdentity reply.
func parseListIdentity(b []byte) *Identity {
	// Item count(2), type(2), length(2), then item data.
	if len(b) < 6 || binary.LittleEndian.Uint16(b[2:4]) != cpfItemIdentity {
		return nil
	}
	d := b[6:]
	if n := int(binary.LittleEndian.Uint16(b[4:6])); n < len(d) {
		d = d[:n]
	}
	if len(d) <= lidName {
		return nil
	}
	vendor := binary.LittleEndian.Uint16(d[lidVendor:])
	devType := binary.LittleEndian.Uint16(d[lidType:])
	id := &Identity{
		Vendor:     cipVendors[vendor],
		DeviceType: cipDeviceTypes[devType],
		Firmware:   fmt.Sprintf("%d.%03d", d[lidRevision], d[lidRevision+1]),
		Serial:     fmt.Sprintf("%08x", binary.LittleEndian.Uint32(d[lidSerial:])),
	}
	if id.Vendor == "" {
		id.Vendor = fmt.Sprintf("CIP vendor %d", vendor)
	}
	if id.DeviceType == "" {
		id.DeviceType = fmt.Sprintf("CIP device type %d", devType)
	}
	nameLen := int(d[lidName])
	if end := lidName + 1 + nameLen; end <= len(d) {
		id.Model = cleanString(d[lidName+1 : end])
	} else {
		id.Model = cleanString(d[lidName+1:])
	}
	return id
}
