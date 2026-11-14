package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
)

// Kernel-side codes; they must match ebpf/cerberus_tc.c.
const (
	kActionDrop uint8 = 1
	kActionLog  uint8 = 2

	kDirSrc uint8 = 1
	kDirDst uint8 = 2
)

// value mirrors struct policy_val.
type value struct {
	Slot   uint32
	Action uint8
	Dir    uint8
	Pad    uint16
}

// Counter is one rule's packet/byte count, summed over CPUs.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Kernel is the set of operations the engine needs from the classifier.
// The production implementation wraps the BPF maps; tests use a fake.
type Kernel interface {
	SetEnforce(on bool) error
	PutMAC(mac net.HardwareAddr, v value) error
	DeleteMAC(mac net.HardwareAddr) error
	PutPrefix(p netip.Prefix, v value) error
	DeletePrefix(p netip.Prefix) error
	ReadCounter(slot uint32) (Counter, error)
	ResetCounter(slot uint32) error

	// WriteChain replaces the whole filter chain atomically.
	WriteChain(rules []filterValue) error
	ReadFilterCounter(slot uint32) (Counter, error)
	ResetFilterCounter(slot uint32) error
}

func encode(r Rule, slot uint32) value {
	v := value{Slot: slot, Action: kActionLog}
	if r.Action == ActionDrop {
		v.Action = kActionDrop
	}
	switch r.Direction {
	case DirectionSrc:
		v.Dir = kDirSrc
	case DirectionDst:
		v.Dir = kDirDst
	default:
		v.Dir = kDirSrc | kDirDst
	}
	return v
}

type macKey struct {
	Addr [6]byte
	Pad  uint16
}

type v4Key struct {
	Prefixlen uint32
	Addr      [4]byte
}

type v6Key struct {
	Prefixlen uint32
	Addr      [16]byte
}

type perCPUCounter struct {
	Packets uint64
	Bytes   uint64
}

// BPFMaps is the production Kernel backed by the loaded collection.
type BPFMaps struct {
	cfg, mac, v4, v6, counters             *ebpf.Map
	filterCfg, filterRules, filterCounters *ebpf.Map
	activeHalf                             uint32 // 0 or 1; the half packets read
}

// MapNames lists the maps NewBPFMaps needs from the collection.
var MapNames = []string{
	"policy_cfg", "policy_mac", "policy_v4", "policy_v6", "policy_counters",
	"filter_cfg", "filter_rules", "filter_counters",
}

// NewBPFMaps picks the policy maps out of a loaded collection.
func NewBPFMaps(maps map[string]*ebpf.Map) (*BPFMaps, error) {
	for _, n := range MapNames {
		if maps[n] == nil {
			return nil, fmt.Errorf("BPF object has no %q map", n)
		}
	}
	return &BPFMaps{
		cfg: maps["policy_cfg"], mac: maps["policy_mac"], v4: maps["policy_v4"],
		v6: maps["policy_v6"], counters: maps["policy_counters"],
		filterCfg: maps["filter_cfg"], filterRules: maps["filter_rules"],
		filterCounters: maps["filter_counters"],
	}, nil
}

// WriteChain writes the inactive half of filter_rules, then publishes it by
// flipping filter_cfg in one 32-bit update (bit 16 = half, low bits = count).
func (b *BPFMaps) WriteChain(rules []filterValue) error {
	if len(rules) > MaxFilterRules {
		return fmt.Errorf("chain has %d rules, max %d", len(rules), MaxFilterRules)
	}
	next := 1 - b.activeHalf
	base := next * MaxFilterRules
	for i, r := range rules {
		if err := b.filterRules.Update(base+uint32(i), r, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write filter rule %d: %w", i, err)
		}
	}
	cfg := next<<16 | uint32(len(rules))
	if err := b.filterCfg.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish filter chain: %w", err)
	}
	b.activeHalf = next
	return nil
}

func (b *BPFMaps) ReadFilterCounter(slot uint32) (Counter, error) {
	return sumPerCPU(b.filterCounters, slot)
}

func (b *BPFMaps) ResetFilterCounter(slot uint32) error {
	return resetPerCPU(b.filterCounters, slot)
}

func (b *BPFMaps) SetEnforce(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return b.cfg.Update(uint32(0), v, ebpf.UpdateAny)
}

func toMACKey(mac net.HardwareAddr) macKey {
	var k macKey
	copy(k.Addr[:], mac)
	return k
}

func (b *BPFMaps) PutMAC(mac net.HardwareAddr, v value) error {
	return b.mac.Update(toMACKey(mac), v, ebpf.UpdateAny)
}

func (b *BPFMaps) DeleteMAC(mac net.HardwareAddr) error {
	return ignoreMissing(b.mac.Delete(toMACKey(mac)))
}

func (b *BPFMaps) PutPrefix(p netip.Prefix, v value) error {
	if p.Addr().Is4() {
		return b.v4.Update(v4Key{Prefixlen: prefixLen(p), Addr: p.Addr().As4()}, v, ebpf.UpdateAny)
	}
	return b.v6.Update(v6Key{Prefixlen: prefixLen(p), Addr: p.Addr().As16()}, v, ebpf.UpdateAny)
}

func (b *BPFMaps) DeletePrefix(p netip.Prefix) error {
	if p.Addr().Is4() {
		return ignoreMissing(b.v4.Delete(v4Key{Prefixlen: prefixLen(p), Addr: p.Addr().As4()}))
	}
	return ignoreMissing(b.v6.Delete(v6Key{Prefixlen: prefixLen(p), Addr: p.Addr().As16()}))
}

func (b *BPFMaps) ReadCounter(slot uint32) (Counter, error) {
	return sumPerCPU(b.counters, slot)
}

func (b *BPFMaps) ResetCounter(slot uint32) error {
	return resetPerCPU(b.counters, slot)
}

func sumPerCPU(m *ebpf.Map, slot uint32) (Counter, error) {
	var perCPU []perCPUCounter
	if err := m.Lookup(slot, &perCPU); err != nil {
		return Counter{}, err
	}
	var c Counter
	for _, p := range perCPU {
		c.Packets += p.Packets
		c.Bytes += p.Bytes
	}
	return c, nil
}

func resetPerCPU(m *ebpf.Map, slot uint32) error {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	return m.Update(slot, make([]perCPUCounter, n), ebpf.UpdateAny)
}

// prefixLen is the LPM key length; netip guarantees 0..128 for valid
// prefixes, the check keeps the conversion provably in range.
func prefixLen(p netip.Prefix) uint32 {
	b := p.Bits()
	if b < 0 || b > 128 {
		return 0
	}
	return uint32(b)
}

func ignoreMissing(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
