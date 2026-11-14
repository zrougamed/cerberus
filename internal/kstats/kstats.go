// Package kstats reads the kernel-side packet counters kept by the TC
// classifier (the "counters" per-CPU array in ebpf/cerberus_tc.c).
package kstats

import "fmt"

// Counter indexes; they must match the CNT_* defines in ebpf/cerberus_tc.c.
const (
	idxTotal uint32 = iota
	idxARP
	idxIPv4
	idxIPv6
	idxOther
	idxRingbufFull
	idxPolicyDrop
	idxFilterLogLost
	numCounters
)

// Counter is the per-CPU value layout of the BPF map (struct counter).
type Counter struct {
	Packets uint64
	Bytes   uint64
}

// Snapshot is the sum of every CPU's counters at one point in time.
type Snapshot struct {
	Total Counter `json:"total"`
	ARP   Counter `json:"arp"`
	IPv4  Counter `json:"ipv4"`
	IPv6  Counter `json:"ipv6"`
	Other Counter `json:"other"`
	// RingbufFull counts events the kernel could not hand to user space
	// because the ring buffer was full. A rising value means the monitor is
	// missing traffic (overload, or an attempt to blind it).
	RingbufFull Counter `json:"ringbuf_full"`
	// PolicyDropped counts packets dropped by an enforced policy rule.
	PolicyDropped Counter `json:"policy_dropped"`
	// FilterLogLost counts filter log events lost to a full log ring buffer.
	FilterLogLost Counter `json:"filter_log_lost"`
}

// PerCPULookup fetches one key of a per-CPU map into a slice with one entry
// per possible CPU. *ebpf.Map satisfies it via its Lookup method.
type PerCPULookup interface {
	Lookup(key, valueOut any) error
}

// Reader turns the raw map into Snapshots.
type Reader struct {
	m PerCPULookup
}

// NewReader wraps the "counters" map of the loaded collection.
func NewReader(m PerCPULookup) *Reader {
	return &Reader{m: m}
}

// Read sums each counter across CPUs.
func (r *Reader) Read() (Snapshot, error) {
	var sums [numCounters]Counter
	for i := range numCounters {
		var perCPU []Counter
		if err := r.m.Lookup(i, &perCPU); err != nil {
			return Snapshot{}, fmt.Errorf("read counter %d: %w", i, err)
		}
		for _, c := range perCPU {
			sums[i].Packets += c.Packets
			sums[i].Bytes += c.Bytes
		}
	}
	return Snapshot{
		Total:         sums[idxTotal],
		ARP:           sums[idxARP],
		IPv4:          sums[idxIPv4],
		IPv6:          sums[idxIPv6],
		Other:         sums[idxOther],
		RingbufFull:   sums[idxRingbufFull],
		PolicyDropped: sums[idxPolicyDrop],
		FilterLogLost: sums[idxFilterLogLost],
	}, nil
}
