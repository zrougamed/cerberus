// Package capture keeps a short in-memory history of raw frames and writes
// pcapng files from it, on demand or when an alert fires.
package capture

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Packet is one captured frame.
type Packet struct {
	Time    time.Time
	Iface   int // index into the capturer's interface list
	Data    []byte
	OrigLen int // length on the wire; Data may be shorter (snaplen)
}

// ring is a FIFO of packets bounded by total bytes and age.
type ring struct {
	mu       sync.Mutex
	buf      []Packet
	start    int // index of the oldest packet in buf
	bytes    int
	maxBytes int
	maxAge   time.Duration
}

func newRing(maxBytes int, maxAge time.Duration) *ring {
	return &ring{maxBytes: maxBytes, maxAge: maxAge}
}

// add appends p and evicts what no longer fits. Packets are expected in
// time order; p.Time is the clock for age eviction.
func (r *ring) add(p Packet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p)
	r.bytes += len(p.Data)
	for r.start < len(r.buf) {
		oldest := r.buf[r.start]
		if r.bytes <= r.maxBytes && p.Time.Sub(oldest.Time) <= r.maxAge {
			break
		}
		r.bytes -= len(oldest.Data)
		r.buf[r.start] = Packet{} // release the data for GC
		r.start++
	}
	// Compact once the dead prefix is half the slice, so memory does not
	// grow with the number of packets ever seen.
	if r.start > len(r.buf)/2 {
		n := copy(r.buf, r.buf[r.start:])
		clear(r.buf[n:])
		r.buf = r.buf[:n]
		r.start = 0
	}
}

// select returns the packets in [from, to] that match. The returned
// packets share data with the ring; Data is never modified after add.
func (r *ring) selectPackets(from, to time.Time, match func(Packet) bool) []Packet {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Packet
	for _, p := range r.buf[r.start:] {
		if p.Time.Before(from) || p.Time.After(to) {
			continue
		}
		if match == nil || match(p) {
			out = append(out, p)
		}
	}
	return out
}

// stats returns the packet count, bytes and oldest timestamp held.
func (r *ring) stats() (packets, bytes int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	packets = len(r.buf) - r.start
	if packets > 0 {
		oldest = r.buf[r.start].Time
	}
	return packets, r.bytes, oldest
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
