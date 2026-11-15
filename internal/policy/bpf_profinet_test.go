package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Offsets in struct network_event (see ebpf/cerberus_tc.c and
// models.NetworkEvent): event_type at 0, src_mac at 1, l7_payload last.
const (
	evTypeOff     = 0
	evSrcMACOff   = 1
	evPayloadOff  = 208 - 128
	eventProfinet = 8
)

// dcpFrame builds a PROFINET DCP frame: optional 802.1Q tag, ethertype
// 0x8892, frame id, then a minimal DCP header and pad to 60 bytes.
func dcpFrame(vlan bool, frameID uint16) []byte {
	b := []byte{0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0x77} // multicast dst, src 02:..:77
	if vlan {
		b = append(b, 0x81, 0x00, 0xc0, 0x00) // priority 6, VLAN 0
	}
	b = append(b, 0x88, 0x92)
	b = binary.BigEndian.AppendUint16(b, frameID)
	b = append(b, 0x05, 0x00, 0, 0, 0, 1, 0, 1, 0, 4, 0xff, 0xff, 0, 0) // identify, all selector
	for len(b) < 60 {
		b = append(b, 0)
	}
	return b
}

// drainEvents returns the event records currently in the events ring.
func drainEvents(t *testing.T, r *ringbuf.Reader) [][]byte {
	t.Helper()
	var out [][]byte
	for {
		r.SetDeadline(time.Now().Add(50 * time.Millisecond))
		rec, err := r.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return out
		}
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		out = append(out, rec.RawSample)
	}
}

// TestBPF_ProfinetDCPEvents runs crafted frames through the classifier:
// DCP frames (tagged or not) become events with the frame from the frame id
// on; cyclic real-time frames and truncated frames do not.
func TestBPF_ProfinetDCPEvents(t *testing.T) {
	coll, prog := loadClassifier(t)
	events, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"identify request", dcpFrame(false, 0xFEFE), true},
		{"vlan tagged set", dcpFrame(true, 0xFEFD), true},
		{"identify response", dcpFrame(false, 0xFEFF), true},
		{"hello", dcpFrame(true, 0xFEFC), true},
		{"cyclic real-time data", dcpFrame(false, 0x8000), false},
		{"tagged cyclic data", dcpFrame(true, 0xC000), false},
		{"other ethertype in vlan", func() []byte { f := dcpFrame(true, 0xFEFE); f[16], f[17] = 0x88, 0xA4; return f }(), false},
		{"truncated after ethertype", dcpFrame(false, 0xFEFE)[:15], false},
		{"truncated vlan tag", dcpFrame(true, 0xFEFE)[:16], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := prog.Run(&ebpf.RunOptions{Data: tt.frame})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if ret != verdictNext {
				t.Fatalf("verdict %#x, want pass to the next program", ret)
			}
			got := drainEvents(t, events)
			if !tt.want {
				if len(got) != 0 {
					t.Fatalf("emitted %d events", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("emitted %d events, want 1", len(got))
			}
			ev := got[0]
			if ev[evTypeOff] != eventProfinet || ev[evSrcMACOff+5] != 0x77 {
				t.Fatalf("event type %d, src MAC byte %#x", ev[evTypeOff], ev[evSrcMACOff+5])
			}
			start := 14
			if tt.frame[12] == 0x81 {
				start = 18
			}
			want := tt.frame[start:]
			if !bytes.Equal(ev[evPayloadOff:evPayloadOff+len(want)], want) {
				t.Fatalf("payload % x, want % x", ev[evPayloadOff:evPayloadOff+len(want)], want)
			}
		})
	}
}
