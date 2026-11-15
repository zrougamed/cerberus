// Package capture keeps a short in-memory history of raw frames and writes
// pcapng files from it, on demand or when an alert fires.
package capture

import (
	"encoding/binary"
	"math"
	"net/netip"
	"sync"
	"time"
)

// Packet is one captured frame, as handed to the pcapng writer.
type Packet struct {
	Time    time.Time
	Iface   int // index into the capturer's interface list
	Data    []byte
	OrigLen int // length on the wire; Data may be shorter (snaplen)
}

// Each frame is stored inline in the arena as a record:
//
//	ts      int64   unix nanoseconds
//	origLen uint32  length on the wire
//	capLen  uint16  bytes stored
//	iface   uint16  interface index
//	data    [capLen]byte, padded to 8 bytes
//
// A record never wraps: when it does not fit before the end, a marker with
// capLen = wrapMarker is written and the record starts at offset 0.
const (
	recHeaderLen = 16
	recAlign     = 8
	wrapMarker   = 0xFFFF
	maxCapLen    = wrapMarker - 1
)

func recordLen(capLen int) int {
	return (recHeaderLen + capLen + recAlign - 1) &^ (recAlign - 1)
}

// ring is a FIFO of frames in one preallocated byte arena, bounded by size
// and age. Adding a frame copies it once and allocates nothing, so memory
// stays at the configured size and the garbage collector has no per-frame
// work.
type ring struct {
	mu      sync.Mutex
	buf     []byte
	head    int // next write offset
	tail    int // oldest record offset
	used    int // bytes between tail and head, including wrap gaps
	packets int
	maxAge  int64 // nanoseconds
}

func newRing(maxBytes int, maxAge time.Duration) *ring {
	// Round down to the record alignment so a full ring ends on a record
	// boundary.
	return &ring{buf: make([]byte, maxBytes&^(recAlign-1)), maxAge: maxAge.Nanoseconds()}
}

// appendFrame stores one frame. Caller holds r.mu. Frames are expected in
// time order; ts is the clock for age eviction.
func (r *ring) appendFrame(ts int64, iface int, data []byte, origLen int) {
	capLen := len(data)
	if capLen > maxCapLen {
		capLen = maxCapLen
	}
	need := recordLen(capLen)
	if need > len(r.buf) {
		return // larger than the whole ring; cannot be kept
	}
	// Evict by age first, then until the record fits.
	for r.packets > 0 && ts-r.ts(r.tail) > r.maxAge {
		r.evict()
	}
	for r.packets > 0 && !r.fits(need) {
		r.evict()
	}
	if r.packets == 0 {
		r.head, r.tail, r.used = 0, 0, 0
	}
	if r.head+need > len(r.buf) {
		// fits() found room at the start: mark the rest of the arena as a
		// gap and continue at 0.
		if len(r.buf)-r.head >= recHeaderLen {
			binary.LittleEndian.PutUint16(r.buf[r.head+12:], wrapMarker)
		}
		r.used += len(r.buf) - r.head
		r.head = 0
	}
	h := r.buf[r.head:]
	if ts < 0 {
		ts = 0
	}
	if iface < 0 || iface > maxCapLen {
		iface = 0
	}
	binary.LittleEndian.PutUint64(h[0:], uint64(ts))
	binary.LittleEndian.PutUint32(h[8:], u32(origLen))
	binary.LittleEndian.PutUint16(h[12:], uint16(capLen))
	binary.LittleEndian.PutUint16(h[14:], uint16(iface))
	copy(h[recHeaderLen:], data[:capLen])
	r.head += need
	r.used += need
	r.packets++
}

// fits reports whether need contiguous bytes are free, at head or, after
// a wrap, at the start of the arena. Callers check r.packets > 0 first.
func (r *ring) fits(need int) bool {
	if r.head > r.tail {
		// Free space is [head, end) and [0, tail).
		return r.head+need <= len(r.buf) || need <= r.tail
	}
	return r.head+need <= r.tail
}

func (r *ring) ts(off int) int64 {
	v := binary.LittleEndian.Uint64(r.buf[off:])
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// evict drops the oldest record, skipping a wrap gap if one follows.
func (r *ring) evict() {
	capLen := int(binary.LittleEndian.Uint16(r.buf[r.tail+12:]))
	n := recordLen(capLen)
	r.tail += n
	r.used -= n
	r.packets--
	r.skipGap()
}

// skipGap moves tail past a wrap marker or the unusable end of the arena.
func (r *ring) skipGap() {
	if r.packets == 0 {
		r.head, r.tail, r.used = 0, 0, 0
		return
	}
	if len(r.buf)-r.tail < recHeaderLen || binary.LittleEndian.Uint16(r.buf[r.tail+12:]) == wrapMarker {
		r.used -= len(r.buf) - r.tail
		r.tail = 0
	}
}

// add stores one frame; for tests and callers outside a block.
func (r *ring) add(p Packet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appendFrame(p.Time.UnixNano(), p.Iface, p.Data, p.OrigLen)
}

// selectPackets copies out the frames in [from, to] that match.
func (r *ring) selectPackets(from, to time.Time, match func(Packet) bool) []Packet {
	r.mu.Lock()
	defer r.mu.Unlock()
	lo, hi := from.UnixNano(), to.UnixNano()
	var out []Packet
	off := r.tail
	for range r.packets {
		if len(r.buf)-off < recHeaderLen || binary.LittleEndian.Uint16(r.buf[off+12:]) == wrapMarker {
			off = 0
		}
		h := r.buf[off:]
		ts := r.ts(off)
		capLen := int(binary.LittleEndian.Uint16(h[12:]))
		off += recordLen(capLen)
		if ts < lo || ts > hi {
			continue
		}
		p := Packet{
			Time:    time.Unix(0, ts),
			Iface:   int(binary.LittleEndian.Uint16(h[14:])),
			Data:    h[recHeaderLen : recHeaderLen+capLen],
			OrigLen: int(binary.LittleEndian.Uint32(h[8:])),
		}
		if match == nil || match(p) {
			p.Data = append([]byte(nil), p.Data...) // the arena is reused
			out = append(out, p)
		}
	}
	return out
}

// stats returns the packet count, bytes held and oldest timestamp.
func (r *ring) stats() (packets, bytes int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.packets > 0 {
		oldest = time.Unix(0, r.ts(r.tail))
	}
	return r.packets, r.used, oldest
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88A8
	ethHeaderLen  = 14
	vlanTagLen    = 4
)

// hasAddr reports whether an Ethernet frame's IPv4, IPv6 or ARP addresses
// include addr. VLAN tags (802.1Q, 802.1ad) are skipped.
func hasAddr(frame []byte, addr netip.Addr) bool {
	if len(frame) < ethHeaderLen {
		return false
	}
	off := 12
	etype := binary.BigEndian.Uint16(frame[off:])
	for etype == etherTypeVLAN || etype == etherTypeQinQ {
		off += vlanTagLen
		if len(frame) < off+2 {
			return false
		}
		etype = binary.BigEndian.Uint16(frame[off:])
	}
	l3 := frame[off+2:]
	addr = addr.Unmap()
	switch etype {
	case etherTypeIPv4:
		return addr.Is4() && len(l3) >= 20 && (match4(l3[12:16], addr) || match4(l3[16:20], addr))
	case etherTypeIPv6:
		return addr.Is6() && len(l3) >= 40 && (match16(l3[8:24], addr) || match16(l3[24:40], addr))
	case etherTypeARP:
		// Ethernet/IPv4 ARP: sender IP at 14, target IP at 24.
		return addr.Is4() && len(l3) >= 28 && (match4(l3[14:18], addr) || match4(l3[24:28], addr))
	}
	return false
}

func match4(b []byte, addr netip.Addr) bool {
	return netip.AddrFrom4([4]byte(b)) == addr
}

func match16(b []byte, addr netip.Addr) bool {
	return netip.AddrFrom16([16]byte(b)) == addr
}
