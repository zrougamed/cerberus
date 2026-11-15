package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Styles. Colours are dropped by the renderer when NO_COLOR is set or the
// terminal has none.
var (
	stBold   = lipgloss.NewStyle().Bold(true)
	stDim    = lipgloss.NewStyle().Faint(true)
	stTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E0B23C"))
	stTabOn  = lipgloss.NewStyle().Bold(true).Reverse(true)
	stSel    = lipgloss.NewStyle().Reverse(true)
	stHigh   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F5F"))
	stMedium = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAF00"))
	stLow    = lipgloss.NewStyle().Foreground(lipgloss.Color("#5FAFFF"))
	stOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("#5FD787"))
	stChart  = lipgloss.NewStyle().Foreground(lipgloss.Color("#5FAFD7"))
)

// severityStyle colours a severity word.
func severityStyle(sev string) lipgloss.Style {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return stHigh
	case "medium", "warning":
		return stMedium
	case "low", "info":
		return stLow
	}
	return lipgloss.NewStyle()
}

// clip shortens s to width display columns, ending with … when cut.
func clip(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= width {
		return s
	}
	return ansi.Truncate(s, width, "…")
}

// pad clips or right-pads s to exactly width display columns.
func pad(s string, width int) string {
	s = clip(s, width)
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidth(s)))
}

// section is a bold heading line.
func section(title string) string { return stTitle.Render(title) }

// ago formats how long before now t was: 4s, 12m, 3h, 2d. Zero is "never".
func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// clock formats a timestamp in local time; today shows only the time.
func clock(t, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	t = t.In(now.Location())
	y1, m1, d1 := t.Date()
	y2, m2, d2 := now.Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04:05")
	}
	return t.Format("01-02 15:04")
}

func stripStyles(s string) string { return ansi.Strip(s) }

func itoa(n int) string { return strconv.Itoa(n) }

// orDash returns s, or "-" when empty.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
