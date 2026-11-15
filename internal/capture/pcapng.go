package capture

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

// pcapng block types and constants (draft-ietf-opsawg-pcapng).
const (
	blockSHB         = 0x0A0D0D0A
	blockIDB         = 0x00000001
	blockEPB         = 0x00000006
	byteOrderMagic   = 0x1A2B3C4D
	linkTypeEthernet = 1
	optEnd           = 0
	optIfName        = 2
	optShbUserApp    = 4
)

// Interface describes one capture interface in the file.
type Interface struct {
	Name    string
	Snaplen int
}

// writePcapng writes a section with one interface block per interface and
// one enhanced packet block per packet. Timestamps use the default
// microsecond resolution.
func writePcapng(w io.Writer, ifaces []Interface, pkts []Packet) error {
	var b bytes.Buffer
	writeBlock(&b, blockSHB, func(body *bytes.Buffer) {
		le(body, uint32(byteOrderMagic))
		le(body, uint16(1)) // major
		le(body, uint16(0)) // minor
		le(body, int64(-1)) // section length unknown
		writeOption(body, optShbUserApp, []byte("cerberus"))
		writeOption(body, optEnd, nil)
	})
	for _, ifc := range ifaces {
		writeBlock(&b, blockIDB, func(body *bytes.Buffer) {
			le(body, uint16(linkTypeEthernet))
			le(body, uint16(0)) // reserved
			le(body, u32(ifc.Snaplen))
			writeOption(body, optIfName, []byte(ifc.Name))
			writeOption(body, optEnd, nil)
		})
	}
	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}
	for _, p := range pkts {
		b.Reset()
		writeBlock(&b, blockEPB, func(body *bytes.Buffer) {
			// Timestamp: high 32 bits first, then low, each little-endian.
			var ts [8]byte
			binary.LittleEndian.PutUint64(ts[:], uint64(max(p.Time.UnixMicro(), 0)))
			le(body, u32(p.Iface))
			body.Write(ts[4:8])
			body.Write(ts[0:4])
			le(body, u32(len(p.Data)))
			le(body, u32(p.OrigLen))
			body.Write(p.Data)
			pad(body, len(p.Data))
		})
		if _, err := w.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// writeBlock frames body as a pcapng block: type, total length, body,
// total length again.
func writeBlock(b *bytes.Buffer, typ uint32, fill func(*bytes.Buffer)) {
	var body bytes.Buffer
	fill(&body)
	total := u32(12 + body.Len())
	le(b, typ)
	le(b, total)
	b.Write(body.Bytes())
	le(b, total)
}

func writeOption(b *bytes.Buffer, code uint16, value []byte) {
	le(b, code)
	n := len(value)
	if n > math.MaxUint16 {
		n = math.MaxUint16
	}
	value = value[:n]
	le(b, uint16(n))
	b.Write(value)
	pad(b, len(value))
}

func pad(b *bytes.Buffer, n int) {
	if r := n % 4; r != 0 {
		b.Write(make([]byte, 4-r))
	}
}

// u32 clamps n into the uint32 range pcapng fields use.
func u32(n int) uint32 {
	switch {
	case n < 0:
		return 0
	case int64(n) > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(n)
}

func le(b *bytes.Buffer, v any) {
	_ = binary.Write(b, binary.LittleEndian, v) // bytes.Buffer writes cannot fail
}
