package kstats

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// TestObjectCountersMapMatchesLayout checks the compiled BPF object (built by
// `make bpf`) against this package, so a change on one side without the other
// fails here instead of at load time. Skipped when the object is not built.
func TestObjectCountersMapMatchesLayout(t *testing.T) {
	const obj = "../../build/cerberus_tc.o"
	if _, err := os.Stat(obj); errors.Is(err, os.ErrNotExist) {
		t.Skip("build/cerberus_tc.o not built; run make bpf")
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	m := spec.Maps["counters"]
	if m == nil {
		t.Fatal("object has no 'counters' map")
	}
	if m.Type != ebpf.PerCPUArray {
		t.Errorf("type: got %v, want PerCPUArray", m.Type)
	}
	if m.MaxEntries != numCounters {
		t.Errorf("max_entries: got %d, want %d", m.MaxEntries, numCounters)
	}
	if m.KeySize != 4 {
		t.Errorf("key size: got %d, want 4", m.KeySize)
	}
	if want := uint32(unsafe.Sizeof(Counter{})); m.ValueSize != want {
		t.Errorf("value size: got %d, want %d", m.ValueSize, want)
	}
}
