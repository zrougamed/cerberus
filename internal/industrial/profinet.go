package industrial

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// PROFINET DCP (IEC 61158-6-10 section 4.3). The payload starts at the
// frame id, after the ethertype and any VLAN tag; the TC program only
// reports frame ids 0xFEFC-0xFEFF.
const (
	dcpFrameHello     = 0xFEFC // lowest DCP frame id
	dcpFrameIdentResp = 0xFEFF // highest DCP frame id
	dcpHeaderLen      = 12     // frame id, service id, type, xid(4), delay(2), data length(2)
	dcpBlockHeaderLen = 4      // option, suboption, block length(2)
	dcpBlockInfoLen   = 2      // BlockInfo in responses, BlockQualifier in Set requests

	dcpServiceGet      = 1
	dcpServiceSet      = 2
	dcpServiceIdentify = 3
	dcpServiceHello    = 4
	dcpTypeRequest     = 0

	dcpOptIP      = 0x01
	dcpOptDevice  = 0x02
	dcpOptControl = 0x05

	dcpSubIPParam       = 0x02
	dcpSubTypeOfStation = 0x01
	dcpSubNameOfStation = 0x02
	dcpSubDeviceID      = 0x03
	dcpSubSignal        = 0x03
	dcpSubFactoryReset  = 0x05
	dcpSubResetFactory  = 0x06
)

// PROFINET vendor ids (PI vendor list). Unknown ids are shown as numbers.
var profinetVendors = map[uint16]string{
	0x002A: "Siemens AG",
}

// dcpBlock is one TLV block of a DCP message.
type dcpBlock struct {
	opt, sub uint8
	data     []byte // after the block header
}

// DecodeDCP parses a PROFINET DCP frame. Identify responses and Hello
// messages yield the station's identity; Set requests that rename a
// station, change its address or reset it to factory settings are classed
// as write or control.
func DecodeDCP(p []byte) (Message, bool) {
	if len(p) < dcpHeaderLen {
		return Message{}, false
	}
	frameID := binary.BigEndian.Uint16(p[0:2])
	service, stype := p[2], p[3]
	if frameID < dcpFrameHello || frameID > dcpFrameIdentResp || service < dcpServiceGet || service > dcpServiceHello {
		return Message{}, false
	}
	dataLen := int(binary.BigEndian.Uint16(p[10:12]))
	body := p[dcpHeaderLen:]
	if dataLen < len(body) {
		body = body[:dataLen]
	}
	blocks := dcpBlocks(body)

	m := Message{Protocol: ProtocolProfinet, Function: service, Class: ClassOther, Response: stype != dcpTypeRequest}
	switch service {
	case dcpServiceIdentify:
		m.FunctionName = "identify"
	case dcpServiceGet:
		m.FunctionName = "get"
	case dcpServiceHello:
		// A device announcing itself: treated as server traffic.
		m.FunctionName, m.Response = "hello", true
	case dcpServiceSet:
		m.FunctionName = "set"
		if !m.Response {
			m.FunctionName, m.Class, m.Detail = dcpSetAction(blocks)
		}
	}
	if m.Response && (service == dcpServiceIdentify || service == dcpServiceHello) {
		m.Identity, m.Detail = dcpIdentity(blocks)
	}
	if m.Response && stype&0x04 != 0 {
		m.Exception = stype // "request not supported" and other error types
	}
	return m, true
}

// dcpBlocks walks the TLV blocks; blocks are padded to an even length.
func dcpBlocks(b []byte) []dcpBlock {
	var out []dcpBlock
	for len(b) >= dcpBlockHeaderLen {
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if dcpBlockHeaderLen+n > len(b) {
			break
		}
		out = append(out, dcpBlock{opt: b[0], sub: b[1], data: b[dcpBlockHeaderLen : dcpBlockHeaderLen+n]})
		step := dcpBlockHeaderLen + n + n%2
		if step > len(b) {
			break
		}
		b = b[step:]
	}
	return out
}

// dcpSetAction picks the most consequential block of a Set request.
func dcpSetAction(blocks []dcpBlock) (name string, class Class, detail string) {
	name, class = "set", ClassOther
	for _, b := range blocks {
		if len(b.data) < dcpBlockInfoLen {
			continue
		}
		value := b.data[dcpBlockInfoLen:]
		switch {
		case b.opt == dcpOptControl && (b.sub == dcpSubFactoryReset || b.sub == dcpSubResetFactory):
			return "set_factory_reset", ClassControl, ""
		case b.opt == dcpOptIP && b.sub == dcpSubIPParam && class != ClassWrite:
			name, class = "set_ip", ClassWrite
			if len(value) >= 4 {
				detail = "new address " + netip.AddrFrom4([4]byte(value[:4])).String()
			}
		case b.opt == dcpOptDevice && b.sub == dcpSubNameOfStation && class != ClassWrite:
			name, class, detail = "set_name", ClassWrite, "new name "+cleanString(value)
		case b.opt == dcpOptControl && b.sub == dcpSubSignal && class == ClassOther:
			name = "set_signal" // flash the station's LED, used to locate it
		}
	}
	return name, class, detail
}

// dcpIdentity reads TypeOfStation, NameOfStation and DeviceID from an
// Identify response or Hello. Each block's data starts with BlockInfo.
func dcpIdentity(blocks []dcpBlock) (*Identity, string) {
	id := &Identity{DeviceType: "PROFINET device"}
	var station string
	for _, b := range blocks {
		if b.opt != dcpOptDevice || len(b.data) < dcpBlockInfoLen {
			continue
		}
		v := b.data[dcpBlockInfoLen:]
		switch b.sub {
		case dcpSubTypeOfStation:
			id.Model = cleanString(v)
		case dcpSubNameOfStation:
			station = cleanString(v)
		case dcpSubDeviceID:
			if len(v) >= 4 {
				vendor := binary.BigEndian.Uint16(v[0:2])
				id.Vendor = profinetVendors[vendor]
				if id.Vendor == "" {
					id.Vendor = fmt.Sprintf("PROFINET vendor 0x%04x", vendor)
				}
				// The device id names the product type within the vendor,
				// not the individual unit.
				id.DeviceType = fmt.Sprintf("PROFINET device 0x%04x", binary.BigEndian.Uint16(v[2:4]))
			}
		}
	}
	if station == "" {
		return id, ""
	}
	return id, "station " + station
}
