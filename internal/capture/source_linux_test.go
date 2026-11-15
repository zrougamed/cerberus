//go:build linux

package capture

import (
	"context"
	"errors"
	"net"
	"strings"
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
	if s.Name() != "lo" || htons(0x0003) != 0x0300 {
		t.Fatal("name or byte order wrong")
	}
}

// TestAFPacketSource_Loopback reads real frames from lo. It needs
// CAP_NET_RAW, so it skips for unprivileged runs.
func TestAFPacketSource_Loopback(t *testing.T) {
	s, err := NewInterfaceSource("lo", 64)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan int, 64)
	errc := make(chan error, 1)
	go func() {
		errc <- s.Run(ctx, func(data []byte, orig int) {
			if len(data) > 64 || orig < len(data) {
				t.Errorf("frame %d/%d exceeds snaplen", len(data), orig)
			}
			select {
			case got <- orig:
			default:
			}
		})
	}()
	select {
	case err := <-errc:
		if errors.Is(err, unix.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("needs CAP_NET_RAW")
		}
		t.Fatalf("source stopped: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// Generate loopback traffic larger than the snaplen.
	conn, err := net.Dial("udp", "127.0.0.1:9")
	if err == nil {
		_, _ = conn.Write(make([]byte, 200))
		_ = conn.Close()
	}
	select {
	case n := <-got:
		if n <= 64 {
			t.Logf("first frame %d bytes", n)
		}
	case <-ctx.Done():
		t.Fatal("no frame read from lo")
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("run: %v", err)
	}
}
