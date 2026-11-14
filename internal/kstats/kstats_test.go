package kstats

import (
	"errors"
	"testing"
)

// fakeMap stands in for the per-CPU BPF array: key -> one value per CPU.
type fakeMap struct {
	values map[uint32][]Counter
	err    error
}

func (f *fakeMap) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	out := valueOut.(*[]Counter)
	*out = append([]Counter(nil), f.values[key.(uint32)]...)
	return nil
}

func TestRead_SumsAcrossCPUs(t *testing.T) {
	t.Parallel()
	m := &fakeMap{values: map[uint32][]Counter{
		idxTotal:       {{Packets: 10, Bytes: 1000}, {Packets: 5, Bytes: 500}},
		idxARP:         {{Packets: 1, Bytes: 60}, {Packets: 0, Bytes: 0}},
		idxIPv4:        {{Packets: 7, Bytes: 700}, {Packets: 4, Bytes: 400}},
		idxIPv6:        {{Packets: 2, Bytes: 240}, {Packets: 1, Bytes: 100}},
		idxOther:       {{}, {}},
		idxRingbufFull: {{Packets: 3, Bytes: 300}, {Packets: 1, Bytes: 64}},
		idxPolicyDrop:  {{Packets: 2, Bytes: 120}, {Packets: 2, Bytes: 80}},
	}}

	got, err := NewReader(m).Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := Snapshot{
		Total:         Counter{Packets: 15, Bytes: 1500},
		ARP:           Counter{Packets: 1, Bytes: 60},
		IPv4:          Counter{Packets: 11, Bytes: 1100},
		IPv6:          Counter{Packets: 3, Bytes: 340},
		RingbufFull:   Counter{Packets: 4, Bytes: 364},
		PolicyDropped: Counter{Packets: 4, Bytes: 200},
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRead_MissingKeysAreZero(t *testing.T) {
	t.Parallel()
	got, err := NewReader(&fakeMap{values: map[uint32][]Counter{}}).Read()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != (Snapshot{}) {
		t.Fatalf("expected zero snapshot, got %+v", got)
	}
}

func TestRead_PropagatesLookupError(t *testing.T) {
	t.Parallel()
	_, err := NewReader(&fakeMap{err: errors.New("boom")}).Read()
	if err == nil {
		t.Fatal("expected error")
	}
}
