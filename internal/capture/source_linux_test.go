//go:build linux

package capture

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewInterfaceSource(t *testing.T) {
	t.Parallel()
	if _, err := NewInterfaceSource("does-not-exist0", 1518); err == nil {
		t.Fatal("unknown interface accepted")
	}
	s, err := NewInterfaceSource("lo", 1518)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "lo" || htons(0x0003) != 0x0300 || fdInt32(7) != 7 || fdInt32(-1) != -1 {
		t.Fatal("name, byte order or fd conversion wrong")
	}
}

// countSink records frame sizes from a source.
type countSink struct {
	mu     sync.Mutex
	frames []int
	wire   []int
	drops  uint64
}

func (s *countSink) Frames(fill func(add func(int64, []byte, int))) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fill(func(_ int64, data []byte, wire int) {
		s.frames = append(s.frames, len(data))
		s.wire = append(s.wire, wire)
	})
}
func (s *countSink) Drops(n uint64) { s.mu.Lock(); s.drops += n; s.mu.Unlock() }

// TestAFPacketSource_Loopback reads real frames from lo through the
// TPACKET_V3 ring. It needs CAP_NET_RAW, so it skips for unprivileged runs.
func TestAFPacketSource_Loopback(t *testing.T) {
	s, err := NewInterfaceSource("lo", 64)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink := &countSink{}
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx, sink) }()
	select {
	case err := <-errc:
		if errors.Is(err, unix.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("needs CAP_NET_RAW")
		}
		t.Fatalf("source stopped: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// Frames larger than the snaplen: the kernel filter must cut them.
	if conn, err := net.Dial("udp", "127.0.0.1:9"); err == nil {
		for range 20 {
			_, _ = conn.Write(make([]byte, 200))
		}
		_ = conn.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.frames)
		sink.mu.Unlock()
		if n >= 20 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("run: %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.frames) < 20 {
		t.Fatalf("read %d frames from lo, want at least 20", len(sink.frames))
	}
	for i, n := range sink.frames {
		if n > 64 || sink.wire[i] < n {
			t.Fatalf("frame %d: %d bytes kept of %d, snaplen 64", i, n, sink.wire[i])
		}
	}
}
