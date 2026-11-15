package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/zrougamed/cerberus/internal/models"
)

type view int

const (
	viewOverview view = iota
	viewDevices
	viewAlerts
	viewAnomalies
	viewAssets
	viewZones
	viewBaseline
	viewPolicy
	viewCaptures
	viewDNS
	viewCount
)

var viewNames = [viewCount]string{"Overview", "Devices", "Alerts", "Anomalies", "Assets", "Zones", "Baseline", "Policy", "Captures", "DNS/TLS"}

// viewKey is the number key that opens each view.
func viewKey(v view) string { return fmt.Sprint((int(v) + 1) % 10) }

// historyLen is the number of samples kept for the charts: four minutes
// at the default two-second refresh.
const historyLen = 120

var roleRank = map[string]int{"none": 0, "viewer": 1, "analyst": 2, "admin": 3}

// promptKind is what a one-line prompt at the bottom is asking for.
type promptKind int

const (
	promptNone promptKind = iota
	promptFilter
	promptAck
	promptConfirm
)

type prompt struct {
	kind   promptKind
	label  string
	input  []rune
	target string   // alert id for ack
	ids    []string // flow ids for confirm
	action string   // approve or forget
}

type model struct {
	c        *Client
	interval time.Duration
	now      func() time.Time

	view          view
	width, height int
	snap          snapshot
	fetchedAt     time.Time
	err           error
	inflight      bool
	paused        bool
	help          bool

	sel     [viewCount]int
	sortCol [viewCount]int
	filter  [viewCount]string
	prompt  prompt
	marked  map[string]bool // baseline flow ids
	status  string
	detail  bool
	advMAC  string
	alertID string // alert open in detail
	adv     []advisoryMatch
	advErr  error

	pktRate   *history
	protoRate map[string]*history
	score     *history
	lastPkts  map[string]int
	lastAt    time.Time
}

type (
	tickMsg    time.Time
	fetchedMsg struct {
		snap snapshot
		err  error
		at   time.Time
	}
	advMsg struct {
		mac  string
		list []advisoryMatch
		err  error
	}
	actionMsg struct {
		text string
		err  error
	}
)

func newModel(c *Client, interval time.Duration) model {
	return model{
		c: c, interval: interval, now: time.Now, width: 80, height: 24,
		marked: map[string]bool{}, pktRate: newHistory(historyLen), score: newHistory(historyLen),
		protoRate: map[string]*history{}, lastPkts: map[string]int{},
	}
}

func (m model) Init() tea.Cmd { return m.fetchCmd() }

func (m model) fetchCmd() tea.Cmd {
	c, prev, v, now := m.c, m.snap, m.view, m.now
	return func() tea.Msg {
		s, err := fetch(context.Background(), c, prev, v)
		return fetchedMsg{snap: s, err: err, at: now()}
	}
}

func (m model) tick() tea.Cmd {
	return tea.Tick(m.interval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// record adds chart samples from a fresh summary and anomaly snapshot.
func (m *model) record(s snapshot, at time.Time) {
	if s.Anomalies != nil {
		m.score.add(s.Anomalies.CurrentScore)
	}
	if s.Summary == nil {
		return
	}
	dt := at.Sub(m.lastAt).Seconds()
	if !m.lastAt.IsZero() && dt < m.interval.Seconds()/2 {
		return // an extra refresh right after a tick; skip, or it reads as a dip
	}
	for proto, n := range s.Summary.PacketStats {
		h := m.protoRate[proto]
		if h == nil {
			h = newHistory(historyLen)
			m.protoRate[proto] = h
		}
		if prev, ok := m.lastPkts[proto]; ok && dt > 0 && n >= prev {
			r := float64(n-prev) / dt
			h.add(r)
			if proto == "total" {
				m.pktRate.add(r)
			}
		}
		m.lastPkts[proto] = n
	}
	m.lastAt = at
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		if m.paused || m.inflight {
			return m, m.tick()
		}
		m.inflight = true
		return m, tea.Batch(m.fetchCmd(), m.tick())
	case fetchedMsg:
		first := m.fetchedAt.IsZero()
		m.inflight = false
		m.snap, m.err = msg.snap, msg.err
		m.fetchedAt = msg.at
		m.record(msg.snap, msg.at)
		if first {
			return m, m.tick()
		}
		return m, nil
	case advMsg:
		if msg.mac == m.advMAC {
			m.adv, m.advErr = msg.list, msg.err
		}
		return m, nil
	case actionMsg:
		if msg.err != nil {
			m.status = "Failed: " + friendlyErr(msg.err)
		} else {
			m.status = msg.text
		}
		m.inflight = true
		return m, m.fetchCmd()
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

// friendlyErr explains common API refusals in words.
func friendlyErr(err error) string {
	var e *APIError
	if errors.As(err, &e) {
		switch e.Status {
		case 401:
			return "not signed in: set CERBERUS_API_TOKEN or --token-file"
		case 403:
			if e.Msg != "" {
				return e.Msg
			}
			return "your role cannot do this"
		}
	}
	return err.Error()
}

func (m model) can(role string) bool { return roleRank[m.snap.Session.Role] >= roleRank[role] }

func (m model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if m.prompt.kind != promptNone {
		return m.promptKey(k)
	}
	if m.help {
		m.help = false
		return m, nil
	}
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "?":
		m.help = true
		return m, nil
	case "p":
		m.paused = !m.paused
		return m, nil
	case "r":
		if !m.inflight {
			m.inflight = true
			return m, m.fetchCmd()
		}
		return m, nil
	case "tab", "right", "l":
		return m.switchTo((m.view + 1) % viewCount)
	case "shift+tab", "left", "h":
		return m.switchTo((m.view + viewCount - 1) % viewCount)
	case "esc":
		switch {
		case m.detail:
			m.detail = false
		case m.filter[m.view] != "":
			m.filter[m.view] = ""
			m.sel[m.view] = 0
		}
		return m, nil
	case "/":
		if listView(m.view) {
			m.prompt = prompt{kind: promptFilter, label: "Filter", input: []rune(m.filter[m.view])}
		}
		return m, nil
	case "s":
		if listView(m.view) {
			m.sortCol[m.view]++
			m.sel[m.view] = 0
		}
		return m, nil
	case "up", "k":
		m.move(-1)
		return m, nil
	case "down", "j":
		m.move(1)
		return m, nil
	case "pgup":
		m.move(-m.bodyHeight())
		return m, nil
	case "pgdown", " ", "space":
		if key != "pgdown" && m.view == viewBaseline {
			m.toggleMark()
			return m, nil
		}
		m.move(m.bodyHeight())
		return m, nil
	case "g", "home":
		m.sel[m.view] = 0
		return m, nil
	case "G", "end":
		m.sel[m.view] = max(0, m.rowCount()-1)
		return m, nil
	case "enter":
		return m.open()
	case "a":
		return m.startAck()
	case "A", "F":
		return m.startFlowAction(key)
	}
	for v := view(0); v < viewCount; v++ {
		if key == viewKey(v) {
			return m.switchTo(v)
		}
	}
	return m, nil
}

func listView(v view) bool {
	switch v {
	case viewDevices, viewAlerts, viewAssets, viewBaseline, viewCaptures:
		return true
	}
	return false
}

func (m model) switchTo(v view) (tea.Model, tea.Cmd) {
	if v == m.view {
		return m, nil
	}
	m.view, m.detail, m.status = v, false, ""
	if m.inflight {
		return m, nil
	}
	m.inflight = true
	return m, m.fetchCmd()
}

func (m *model) move(d int) {
	if m.detail {
		return
	}
	n := m.rowCount()
	m.sel[m.view] = max(0, min(n-1, m.sel[m.view]+d))
}

func (m model) rowCount() int {
	switch m.view {
	case viewDevices:
		return len(m.deviceRows())
	case viewAlerts:
		return len(m.alertRows())
	case viewAssets:
		return len(m.assetRows())
	case viewBaseline:
		return len(m.flowRows())
	case viewCaptures:
		return len(m.captureRows())
	}
	return 0
}

func (m model) open() (tea.Model, tea.Cmd) {
	switch m.view {
	case viewDevices:
		rows := m.deviceRows()
		if len(rows) == 0 {
			return m, nil
		}
		d := rows[min(m.sel[m.view], len(rows)-1)]
		m.detail, m.advMAC, m.adv, m.advErr = true, d.MAC, nil, nil
		c, mac := m.c, d.MAC
		return m, func() tea.Msg {
			list, err := deviceAdvisories(context.Background(), c, mac)
			return advMsg{mac: mac, list: list, err: err}
		}
	case viewAlerts:
		if a, ok := m.selectedAlert(); ok {
			m.detail, m.alertID = true, a.ID
		}
	}
	return m, nil
}

// selectedAlert is the alert open in detail, or else the highlighted row.
func (m model) selectedAlert() (models.AlertEvent, bool) {
	rows := m.alertRows()
	if m.detail && m.view == viewAlerts {
		for _, a := range rows {
			if a.ID == m.alertID {
				return a, true
			}
		}
	}
	if len(rows) == 0 {
		return models.AlertEvent{}, false
	}
	return rows[min(m.sel[viewAlerts], len(rows)-1)], true
}

func (m model) startAck() (tea.Model, tea.Cmd) {
	if m.view != viewAlerts {
		return m, nil
	}
	a, ok := m.selectedAlert()
	if !ok {
		return m, nil
	}
	if !m.can("analyst") {
		m.status = "Acknowledging needs the analyst role. " + m.accessHint()
		return m, nil
	}
	m.prompt = prompt{kind: promptAck, label: "Note for " + a.Rule + " (optional, Enter to acknowledge)", target: a.ID}
	return m, nil
}

func (m *model) toggleMark() {
	rows := m.flowRows()
	if len(rows) == 0 {
		return
	}
	id := rows[min(m.sel[viewBaseline], len(rows)-1)].ID
	if m.marked[id] {
		delete(m.marked, id)
	} else {
		m.marked[id] = true
	}
	m.move(1)
}

func (m model) startFlowAction(key string) (tea.Model, tea.Cmd) {
	if m.view != viewBaseline {
		return m, nil
	}
	if !m.can("analyst") {
		m.status = "Approving or forgetting flows needs the analyst role. " + m.accessHint()
		return m, nil
	}
	var ids []string
	for _, f := range m.flowRows() {
		if m.marked[f.ID] {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		m.status = "Mark flows with Space first."
		return m, nil
	}
	action, verb := "approve", "Approve"
	if key == "F" {
		action, verb = "forget", "Forget (they alert again if seen)"
	}
	m.prompt = prompt{kind: promptConfirm, label: fmt.Sprintf("%s %d flow(s)? y/n", verb, len(ids)), ids: ids, action: action}
	return m, nil
}

// accessHint says how to get a role, depending on how the console runs.
func (m model) accessHint() string {
	if !m.snap.Session.WritesEnabled {
		return "Changes are turned off on this sensor."
	}
	if !m.snap.Session.Authenticated {
		return "Set CERBERUS_API_TOKEN or use --token-file."
	}
	return "Your role is " + m.snap.Session.Role + "."
}

func (m model) promptKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	p := &m.prompt
	switch k.String() {
	case "esc", "ctrl+c":
		if p.kind == promptFilter {
			m.filter[m.view] = ""
			m.sel[m.view] = 0
		}
		m.prompt = prompt{}
		return m, nil
	case "enter":
		return m.submitPrompt()
	case "backspace":
		if len(p.input) > 0 {
			p.input = p.input[:len(p.input)-1]
		}
	default:
		if p.kind == promptConfirm {
			switch k.String() {
			case "y", "Y":
				return m.submitPrompt()
			case "n", "N":
				m.prompt = prompt{}
			}
			return m, nil
		}
		if t := k.Text; t != "" && len(p.input) < 500 {
			p.input = append(p.input, []rune(t)...)
		}
	}
	if p.kind == promptFilter {
		m.filter[m.view] = string(p.input)
		m.sel[m.view] = 0
	}
	return m, nil
}

func (m model) submitPrompt() (tea.Model, tea.Cmd) {
	p := m.prompt
	m.prompt = prompt{}
	c := m.c
	switch p.kind {
	case promptFilter:
		m.filter[m.view] = strings.TrimSpace(string(p.input))
	case promptAck:
		note := strings.TrimSpace(string(p.input))
		return m, func() tea.Msg {
			err := ackAlert(context.Background(), c, p.target, note)
			return actionMsg{text: "Alert acknowledged.", err: err}
		}
	case promptConfirm:
		m.marked = map[string]bool{}
		return m, func() tea.Msg {
			err := baselineAction(context.Background(), c, p.action, p.ids)
			return actionMsg{text: fmt.Sprintf("%d flow(s): %s done.", len(p.ids), p.action), err: err}
		}
	}
	return m, nil
}

func (m model) bodyHeight() int { return max(1, m.height-3) }

func (m model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "Cerberus " + m.c.Addr()
	return v
}
