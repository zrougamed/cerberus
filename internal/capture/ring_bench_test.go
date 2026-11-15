package capture

import (
	"testing"
	"time"
)

// BenchmarkRingAdd measures storing frames in the history ring, the
// per-frame cost every captured packet pays. The frame is copied into the
// arena; nothing is allocated.
func BenchmarkRingAdd(b *testing.B) {
	for _, size := range []int{64, 1514} {
		b.Run(byteSize(size), func(b *testing.B) {
			r := newRing(32<<20, time.Hour)
			frame := make([]byte, size)
			t0 := time.Now()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := range b.N {
				r.add(Packet{Time: t0.Add(time.Duration(i)), Data: frame, OrigLen: size})
			}
		})
	}
}

func byteSize(n int) string {
	if n < 100 {
		return "small"
	}
	return "full"
}
