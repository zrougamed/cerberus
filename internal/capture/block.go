package capture

import "encoding/binary"

// TPACKET_V3 layouts (linux/if_packet.h), in host byte order.
//
// tpacket_block_desc: version u32, offset_to_priv u32, then tpacket_hdr_v1:
// block_status u32 @8, num_pkts u32 @12, offset_to_first_pkt u32 @16, ...
//
// tpacket3_hdr: tp_next_offset u32 @0, tp_sec u32 @4, tp_nsec u32 @8,
// tp_snaplen u32 @12, tp_len u32 @16, tp_status u32 @20, tp_mac u16 @24.
const (
	blockStatusOff = 8
	blockNumPkts   = 12
	blockFirstPkt  = 16
	blockHdrLen    = 48
	pktHdrLen      = 32

	tpStatusKernel = 0
	tpStatusUser   = 1
)

// walkBlock calls emit for every frame in a TPACKET_V3 block and returns
// how many it emitted. Offsets come from the kernel, but each one is still
// checked against the block so a corrupt block cannot cause a panic.
func walkBlock(block []byte, emit func(ts int64, data []byte, origLen int)) int {
	if len(block) < blockHdrLen {
		return 0
	}
	n := int(binary.NativeEndian.Uint32(block[blockNumPkts:]))
	off := int(binary.NativeEndian.Uint32(block[blockFirstPkt:]))
	emitted := 0
	for range n {
		if off < blockHdrLen || off+pktHdrLen > len(block) {
			break
		}
		h := block[off:]
		next := int(binary.NativeEndian.Uint32(h[0:]))
		sec := int64(binary.NativeEndian.Uint32(h[4:]))
		nsec := int64(binary.NativeEndian.Uint32(h[8:]))
		snap := int(binary.NativeEndian.Uint32(h[12:]))
		wire := int(binary.NativeEndian.Uint32(h[16:]))
		mac := int(binary.NativeEndian.Uint16(h[24:]))
		if mac < pktHdrLen || mac+snap > len(h) {
			break
		}
		emit(sec*1e9+nsec, h[mac:mac+snap], wire)
		emitted++
		if next == 0 {
			break
		}
		off += next
	}
	return emitted
}

// blockReady reports whether the kernel has handed the block to user space.
func blockReady(block []byte) bool {
	return binary.NativeEndian.Uint32(block[blockStatusOff:])&tpStatusUser != 0
}

// releaseBlock hands the block back to the kernel.
func releaseBlock(block []byte) {
	binary.NativeEndian.PutUint32(block[blockStatusOff:], tpStatusKernel)
}
