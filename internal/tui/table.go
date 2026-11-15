package tui

import (
	"strings"
)

// column is one table column: a header and a width. A zero width column
// takes the space left over. When the terminal is too narrow, columns
// with the highest drop value are hidden first; zero never hides.
type column struct {
	title string
	width int
	drop  int
}

// minFlex is the narrowest a flexible column may get before columns are
// hidden.
const minFlex = 12

// table renders rows under a header, showing the window of rows that
// keeps the selected one visible. cells may contain styled text.
type table struct {
	cols     []column
	rows     [][]string
	selected int // -1 for none
	height   int // rows of data that fit
	marked   map[int]bool
}

// layout returns each column's width, 0 for hidden columns. Flexible
// columns share the width left after fixed ones.
func (t table) layout(width int) []int {
	shown := make([]bool, len(t.cols))
	for i := range shown {
		shown[i] = true
	}
	need := func() int {
		n, cols := 0, 0
		for i, c := range t.cols {
			if shown[i] {
				n += max(c.width, minFlex*boolInt(c.width == 0))
				cols++
			}
		}
		return n + max(0, cols-1)
	}
	for need() > width {
		worst := -1
		for i, c := range t.cols {
			if shown[i] && c.drop > 0 && (worst < 0 || c.drop > t.cols[worst].drop) {
				worst = i
			}
		}
		if worst < 0 {
			break
		}
		shown[worst] = false
	}
	ws := make([]int, len(t.cols))
	used, flex, cols := 0, 0, 0
	for i, c := range t.cols {
		if !shown[i] {
			continue
		}
		cols++
		if c.width > 0 {
			ws[i] = c.width
			used += c.width
		} else {
			flex++
		}
	}
	if flex > 0 {
		each := max(4, (width-used-(cols-1))/flex)
		for i, c := range t.cols {
			if shown[i] && c.width == 0 {
				ws[i] = each
			}
		}
	}
	return ws
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// window returns the first visible row for the selection.
func window(selected, total, height int) int {
	if height <= 0 || total <= height || selected < height {
		return 0
	}
	start := selected - height + 1
	return min(start, total-height)
}

func (t table) render(width int) []string {
	ws := t.layout(width)
	line := func(cells []string) string {
		parts := make([]string, 0, len(ws))
		for i, w := range ws {
			if w == 0 {
				continue
			}
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			parts = append(parts, pad(c, w))
		}
		return clip(strings.Join(parts, " "), width)
	}
	titles := make([]string, len(t.cols))
	for i, c := range t.cols {
		titles[i] = c.title
	}
	out := []string{stBold.Render(line(titles))}
	if len(t.rows) == 0 {
		return append(out, stDim.Render("(nothing to show)"))
	}
	start := window(max(t.selected, 0), len(t.rows), t.height)
	end := min(len(t.rows), start+max(1, t.height))
	for i := start; i < end; i++ {
		cells := t.rows[i]
		if t.marked != nil {
			mark := "  "
			if t.marked[i] {
				mark = "✓ "
			}
			cells = append([]string{mark + cells[0]}, cells[1:]...)
		}
		l := line(cells)
		if i == t.selected {
			l = stSel.Render(pad(stripStyles(l), width))
		}
		out = append(out, l)
	}
	if len(t.rows) > end-start {
		out = append(out, stDim.Render(scrollHint(start, end, len(t.rows))))
	}
	return out
}

func scrollHint(start, end, total int) string {
	return "rows " + itoa(start+1) + "-" + itoa(end) + " of " + itoa(total)
}
