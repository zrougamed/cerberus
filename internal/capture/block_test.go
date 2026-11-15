package capture

import (
	"encoding/binary"
	"testing"
)

type blockFrame struct {
	sec, nsec uint32
	data      []byte
	wire      int
}

// buildBlock lays frames out like the kernel: a block header, then one
// tpacket3_hdr per frame with the data at tp_mac, chained by tp_next_offset.
func buildBlock(size int, frames []blockFrame) []byte {
	b := make([]byte, size)
	ne := binary.NativeEndian
	ne.PutUint32(b[blockStatusOff:], tpStatusUser)
	ne.PutUint32(b[blockNumPkts:], uint32(len(frames)))
	ne.PutUint32(b[blockFirstPkt:], blockHdrLen)
	off := blockHdrLen
	for i, f := range frames {
		h := b[off:]
		mac := pktHdrLen + 2 // kernels align the MAC header; any offset works
		next := (mac + len(f.data) + 15) &^ 15
		if i == len(frames)-1 {
			next = 0
		}
		ne.PutUint32(h[0:], uint32(next))
		ne.PutUint32(h[4:], f.sec)
		ne.PutUint32(h[8:], f.nsec)
		ne.PutUint32(h[12:], uint32(len(f.data)))
		ne.PutUint32(h[16:], uint32(f.wire))
		ne.PutUint16(h[24:], uint16(mac))
		copy(h[mac:], f.data)
		off += next
	}
	return b
}

func TestWalkBlock(t *testing.T) {
	t.Parallel()
	frames := []blockFrame{
		{sec: 1763200000, nsec: 250, data: []byte{1, 2, 3}, wire: 60},
		{sec: 1763200001, nsec: 0, data: make([]byte, 1514), wire: 1514},
		{sec: 1763200002, nsec: 999999999, data: []byte{9}, wire: 9000},
	}
	b := buildBlock(1<<14, frames)
	if !blockReady(b) {
		t.Fatal("block not ready")
	}
	var got []blockFrame
	n := walkBlock(b, func(ts int64, data []byte, wire int) {
		got = append(got, blockFrame{sec: uint32(ts / 1e9), nsec: uint32(ts % 1e9), data: append([]byte(nil), data...), wire: wire})
	})
	if n != 3 || len(got) != 3 {
		t.Fatalf("emitted %d", n)
	}
	for i := range frames {
		if got[i].sec != frames[i].sec || got[i].nsec != frames[i].nsec || got[i].wire != frames[i].wire || len(got[i].data) != len(frames[i].data) {
			t.Fatalf("frame %d = %+v, want %+v", i, got[i], frames[i])
		}
	}
	releaseBlock(b)
	if blockReady(b) {
		t.Fatal("block still owned by user space after release")
	}
}

func TestWalkBlock_Corrupt(t *testing.T) {
	t.Parallel()
	good := func() []byte {
		return buildBlock(4096, []blockFrame{{data: []byte{1, 2, 3}, wire: 3}, {data: []byte{4}, wire: 1}})
	}
	ne := binary.NativeEndian
	tests := map[string]func(b []byte) []byte{
		"short block":                func(b []byte) []byte { return b[:20] },
		"first offset inside header": func(b []byte) []byte { ne.PutUint32(b[blockFirstPkt:], 8); return b },
		"first offset past end":      func(b []byte) []byte { ne.PutUint32(b[blockFirstPkt:], 5000); return b },
		"mac offset too small":       func(b []byte) []byte { ne.PutUint16(b[blockHdrLen+24:], 4); return b },
		"snaplen past end":           func(b []byte) []byte { ne.PutUint32(b[blockHdrLen+12:], 1<<20); return b },
		"next offset past end":       func(b []byte) []byte { ne.PutUint32(b[blockHdrLen:], 1<<20); return b },
	}
	want := map[string]int{"next offset past end": 1}
	for name, corrupt := range tests {
		n := walkBlock(corrupt(good()), func(int64, []byte, int) {})
		if n != want[name] {
			t.Errorf("%s: emitted %d, want %d", name, n, want[name])
		}
	}
	// num_pkts larger than the chain: stops at next_offset 0.
	b := good()
	ne.PutUint32(b[blockNumPkts:], 50)
	if n := walkBlock(b, func(int64, []byte, int) {}); n != 2 {
		t.Errorf("overstated count: emitted %d", n)
	}
}

func FuzzWalkBlock(f *testing.F) {
	f.Add(buildBlock(512, []blockFrame{{data: []byte{1, 2, 3}, wire: 3}, {data: []byte{4}, wire: 1}}))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		walkBlock(b, func(ts int64, data []byte, wire int) {
			if len(data) > len(b) {
				t.Fatalf("frame longer than block")
			}
		})
	})
}
