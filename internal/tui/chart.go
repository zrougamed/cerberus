package tui

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
)

// history is a fixed-size ring of samples for the charts. Memory never
// grows past its capacity.
type history struct {
	vals  []float64
	start int
	n     int
}

func newHistory(capacity int) *history { return &history{vals: make([]float64, capacity)} }

func (h *history) add(v float64) {
	if h.n < len(h.vals) {
		h.vals[(h.start+h.n)%len(h.vals)] = v
		h.n++
		return
	}
	h.vals[h.start] = v
	h.start = (h.start + 1) % len(h.vals)
}

// last returns up to n most recent samples, oldest first.
func (h *history) last(n int) []float64 {
	if n > h.n {
		n = h.n
	}
	out := make([]float64, n)
	for i := range n {
		out[i] = h.vals[(h.start+h.n-n+i)%len(h.vals)]
	}
	return out
}

func (h *history) latest() float64 {
	if h.n == 0 {
		return 0
	}
	return h.vals[(h.start+h.n-1)%len(h.vals)]
}

var sparkBlocks = []rune("▁▂▃▄▅▆▇█")

// sparkline draws the last width samples in one line, scaled to their
// own maximum. A flat zero line stays at the bottom.
func sparkline(vals []float64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	maxV := 0.0
	for _, v := range vals {
		maxV = math.Max(maxV, v)
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(vals)))
	for _, v := range vals {
		i := 0
		if maxV > 0 && v > 0 {
			i = int(math.Round(v / maxV * float64(len(sparkBlocks)-1)))
		}
		b.WriteRune(sparkBlocks[i])
	}
	return b.String()
}

// areaChart draws samples as columns height rows tall, using eighth blocks
// for the top of each column. Rows are returned top first.
func areaChart(vals []float64, width, height int) []string {
	if width <= 0 || height <= 0 {
		return nil
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	maxV := 0.0
	for _, v := range vals {
		maxV = math.Max(maxV, v)
	}
	pad := width - len(vals)
	rows := make([]string, height)
	for r := range height {
		var b strings.Builder
		b.WriteString(strings.Repeat(" ", pad))
		floor := float64(height-1-r) * 8 // eighths below this row
		for _, v := range vals {
			eighths := 0.0
			if maxV > 0 {
				eighths = v / maxV * float64(height*8)
			}
			switch fill := eighths - floor; {
			case fill >= 8:
				b.WriteRune('█')
			case fill >= 1:
				b.WriteRune(sparkBlocks[int(fill)-1])
			case r == height-1 && v > 0:
				b.WriteRune('▁') // keep small non-zero values visible
			default:
				b.WriteRune(' ')
			}
		}
		rows[r] = b.String()
	}
	return rows
}

type kv struct {
	key string
	val int
}

// topN returns the n largest entries, ties broken by key.
func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	slices.SortFunc(out, func(a, b kv) int {
		if c := cmp.Compare(b.val, a.val); c != 0 {
			return c
		}
		return cmp.Compare(a.key, b.key)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// barChart draws the n largest entries as labelled horizontal bars that
// fit width columns.
func barChart(m map[string]int, n, width int) []string {
	items := topN(m, n)
	if len(items) == 0 {
		return []string{"(none yet)"}
	}
	labelW, numW := 0, 0
	for _, it := range items {
		labelW = max(labelW, len([]rune(it.key)))
		numW = max(numW, len(humanInt(it.val)))
	}
	labelW = min(labelW, max(8, width/3))
	barW := max(1, min(40, width-labelW-numW-2))
	top := float64(items[0].val)
	out := make([]string, 0, len(items))
	for _, it := range items {
		w := 0
		if top > 0 {
			w = int(math.Round(float64(it.val) / top * float64(barW)))
		}
		if it.val > 0 && w == 0 {
			w = 1
		}
		out = append(out, fmt.Sprintf("%-*s %s%s %*s", labelW, clip(it.key, labelW), strings.Repeat("█", w),
			strings.Repeat(" ", barW-w), numW, humanInt(it.val)))
	}
	return out
}

// humanInt formats counts compactly: 950, 12.4k, 3.1M.
func humanInt(v int) string { return humanCount(float64(v)) }

// humanCount is humanInt for any count, including uint64 kernel counters.
func humanCount(f float64) string {
	switch {
	case math.Abs(f) >= 1e9:
		return fmt.Sprintf("%.1fG", f/1e9)
	case math.Abs(f) >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case math.Abs(f) >= 1e4:
		return fmt.Sprintf("%.1fk", f/1e3)
	}
	return fmt.Sprintf("%.0f", f)
}

// humanBytes formats sizes: 512 B, 3.2 KB, 14.0 MB.
func humanBytes(v int64) string { return humanSize(float64(v)) }

// humanSize is humanBytes for any byte count.
func humanSize(f float64) string {
	switch {
	case f >= 1<<30:
		return fmt.Sprintf("%.1f GB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.1f KB", f/(1<<10))
	}
	return fmt.Sprintf("%.0f B", f)
}

// rate formats a per-second rate.
func rate(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM/s", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.1fk/s", v/1e3)
	case v >= 10:
		return fmt.Sprintf("%.0f/s", v)
	}
	return fmt.Sprintf("%.1f/s", v)
}
