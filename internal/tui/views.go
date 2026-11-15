package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/zrougamed/cerberus/internal/models"
)

// render draws the whole screen: header, tab bar, body and status line.
func (m model) render() string {
	w := max(20, m.width)
	var body []string
	switch {
	case m.help:
		body = helpLines()
	case m.fetchedAt.IsZero() && m.err == nil:
		body = []string{"Connecting to " + m.c.Addr() + "…"}
	case m.fetchedAt.IsZero():
		body = []string{stHigh.Render("Cannot reach Cerberus at " + m.c.Addr()), "", friendlyErr(m.err), "",
			"Check that Cerberus is running and the address is right", "(--addr or CERBERUS_HTTP_ADDR). Retrying…"}
	default:
		body = m.body(w, m.bodyHeight())
	}
	bh := m.bodyHeight()
	if len(body) > bh {
		body = body[:bh]
	}
	for len(body) < bh {
		body = append(body, "")
	}
	lines := append([]string{m.header(w), m.tabs(w)}, body...)
	lines = append(lines, m.footer(w))
	for i, l := range lines {
		lines[i] = clip(l, w)
	}
	return strings.Join(lines, "\n")
}

func (m model) header(w int) string {
	s := m.snap
	role := "read-only"
	if s.Session.Authenticated {
		role = s.Session.Name + " (" + s.Session.Role + ")"
	}
	build := s.Version.Commit
	if build == "" || build == "unknown" {
		build = "dev build"
	}
	state := "live"
	switch {
	case m.paused:
		state = stMedium.Render("paused")
	case m.err != nil && !m.fetchedAt.IsZero():
		state = stHigh.Render("stale: " + clip(friendlyErr(m.err), 40))
	case !m.fetchedAt.IsZero():
		state = "updated " + ago(m.fetchedAt, m.now()) + " ago"
	}
	left := stTitle.Render("Cerberus") + " " + m.c.Addr() + stDim.Render(" ("+build+")")
	right := role + "  " + state
	gap := max(1, w-ansi.StringWidth(left)-ansi.StringWidth(right))
	return left + strings.Repeat(" ", gap) + right
}

func (m model) tabs(w int) string {
	var parts []string
	for v := view(0); v < viewCount; v++ {
		name := viewNames[v]
		if w < 120 { // keep the bar on one line at 80 columns
			name = shortNames[v]
		}
		t := viewKey(v) + " " + name
		if v == m.view {
			t = stTabOn.Render(" " + t + " ")
		} else {
			t = " " + t + " "
		}
		parts = append(parts, t)
	}
	sep := ""
	if w >= 120 {
		sep = " "
	}
	return strings.Join(parts, sep)
}

var shortNames = [viewCount]string{"Over", "Dev", "Alert", "Anom", "Asset", "Zone", "Base", "Pol", "Cap", "DNS"}

func (m model) footer(w int) string {
	if m.prompt.kind != promptNone {
		if m.prompt.kind == promptConfirm {
			return stBold.Render(m.prompt.label)
		}
		return stBold.Render(m.prompt.label+": ") + string(m.prompt.input) + "█"
	}
	if m.status != "" {
		return m.status
	}
	keys := "q quit  ? keys  p pause  r refresh  tab next view"
	if listView(m.view) {
		keys += "  / filter  s sort  enter open"
		if f := m.filter[m.view]; f != "" {
			keys = "filter: " + f + " (esc clears)  " + keys
		}
	}
	switch m.view {
	case viewAlerts:
		if m.can("analyst") {
			keys += "  a acknowledge"
		}
	case viewBaseline:
		if m.can("analyst") {
			keys += "  space mark  A approve  F forget"
		}
	}
	return stDim.Render(clip(keys, w))
}

func helpLines() []string {
	return []string{
		section("Keys"), "",
		"  1-9, 0        open a view (Overview … DNS/TLS)",
		"  tab, ←/→      next or previous view",
		"  ↑/↓, j/k      move; PgUp/PgDn, g/G jump",
		"  enter         open the selected device or alert; esc goes back",
		"  /             filter the list as you type; esc clears it",
		"  s             change the sort column",
		"  p             pause or resume updates;  r refresh now",
		"  a             acknowledge the selected alert (analyst)",
		"  space, A, F   mark baseline flows, then approve or forget them (analyst)",
		"  q             quit", "",
		stDim.Render("Press any key to close."),
	}
}

func (m model) body(w, h int) []string {
	switch m.view {
	case viewOverview:
		return m.overview(w, h)
	case viewDevices:
		if m.detail {
			return m.deviceDetail(w, h)
		}
		return m.devicesView(w, h)
	case viewAlerts:
		if m.detail {
			return m.alertDetail(w)
		}
		return m.alertsView(w, h)
	case viewAnomalies:
		return m.anomaliesView(w, h)
	case viewAssets:
		return m.assetsView(w, h)
	case viewZones:
		return m.zonesView(w)
	case viewBaseline:
		return m.baselineView(w, h)
	case viewPolicy:
		return m.policyView(w, h)
	case viewCaptures:
		return m.capturesView(w, h)
	case viewDNS:
		return m.dnsView(w)
	}
	return nil
}

// columns places two blocks side by side when there is room, else stacks
// them.
func columns(w int, left, right []string) []string {
	if w < 100 {
		return append(append(left, ""), right...)
	}
	lw := w/2 - 1
	out := make([]string, max(len(left), len(right)))
	for i := range out {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out[i] = pad(l, lw) + "  " + clip(r, w-lw-2)
	}
	return out
}

// --- Overview ---

func (m model) overview(w, h int) []string {
	s := m.snap
	cw := w
	if w >= 100 {
		cw = w/2 - 1
	}
	var left []string
	now := m.pktRate.latest()
	peak := 0.0
	for _, v := range m.pktRate.last(historyLen) {
		peak = max(peak, v)
	}
	total := 0
	if s.Summary != nil {
		total = s.Summary.PacketStats["total"]
	}
	left = append(left, section("Traffic")+fmt.Sprintf("  %s now, peak %s, %s packets seen", rate(now), rate(peak), humanInt(total)))
	chartH := 6
	if h < 30 || w < 100 {
		chartH = 3
	}
	if peak == 0 {
		left = append(left, stDim.Render("No traffic in the last few minutes."))
		for range chartH - 1 {
			left = append(left, "")
		}
	} else {
		for _, r := range areaChart(m.pktRate.last(cw), cw, chartH) {
			left = append(left, stChart.Render(r))
		}
	}
	left = append(left, "")
	for _, p := range []string{"tcp", "udp", "dns", "http", "tls", "icmp", "arp"} {
		hh := m.protoRate[p]
		n := 0
		if s.Summary != nil {
			n = s.Summary.PacketStats[p]
		}
		if hh == nil || (n == 0 && p != "tcp" && p != "udp") { // hide protocols never seen
			continue
		}
		sw := max(8, cw-28)
		left = append(left, fmt.Sprintf("%-5s %s %9s %8s", strings.ToUpper(p), stChart.Render(sparkline(hh.last(sw), sw)), rate(hh.latest()), humanInt(n)))
	}

	right := append([]string{section("Status")}, m.statusLines(cw)...)
	if s.Summary != nil {
		right = append(right, "", section("Top services"))
		right = append(right, barChart(s.Summary.TopServices, 5, cw)...)
		right = append(right, "", section("Top vendors"))
		right = append(right, barChart(s.Summary.TopVendors, 5, cw)...)
	}
	out := columns(w, left, right)
	if room := h - len(out) - 2; room > 0 && len(s.Alerts) > 0 {
		out = append(out, "", section("Latest alerts"))
		alerts := latestAlerts(s.Alerts, room)
		for _, a := range alerts {
			out = append(out, fmt.Sprintf("%s  %s  %-16s %s", clock(a.ObservedAt, m.now()), severityStyle(a.Severity).Render(pad(a.Severity, 6)),
				clip(a.Rule, 16), a.Message))
		}
	}
	return out
}

func latestAlerts(all []models.AlertEvent, n int) []models.AlertEvent {
	a := slices.Clone(all)
	slices.SortFunc(a, func(x, y models.AlertEvent) int { return y.ObservedAt.Compare(x.ObservedAt) })
	return a[:min(n, len(a))]
}

func (m model) statusLines(w int) []string {
	s, now := m.snap, m.now()
	var out []string
	if s.Summary != nil {
		out = append(out, fmt.Sprintf("Devices     %d", s.Summary.DeviceCount))
	}
	var hi, med, lo, open int
	for _, a := range s.Alerts {
		if now.Sub(a.ObservedAt) > time.Hour {
			continue
		}
		switch strings.ToLower(a.Severity) {
		case "high", "critical":
			hi++
		case "medium":
			med++
		default:
			lo++
		}
		if a.AckedBy == "" {
			open++
		}
	}
	out = append(out, fmt.Sprintf("Alerts 1h   %s %s %s, %d not acknowledged", stHigh.Render(fmt.Sprintf("%d high", hi)),
		stMedium.Render(fmt.Sprintf("%d medium", med)), stLow.Render(fmt.Sprintf("%d low", lo)), open))
	if a := s.Anomalies; a != nil {
		state := a.Status
		if a.IsAnomaly {
			state = stHigh.Render("ANOMALY")
		}
		sw := max(8, min(30, w-38))
		out = append(out, fmt.Sprintf("Anomaly     %-12s score %5.2f %s", state, a.CurrentScore, stChart.Render(sparkline(m.score.last(sw), sw))))
	}
	if p := s.Policy; p != nil {
		mode := p.Mode
		if mode == "enforce" {
			mode = stHigh.Render("enforcing")
		} else {
			mode = "dry run"
		}
		attached := stOK.Render("attached")
		if !p.KernelAttached {
			attached = stMedium.Render("not attached")
		}
		out = append(out, fmt.Sprintf("Policy      %s, kernel %s, %d rules, %d filters", mode, attached, len(p.Rules), len(p.Filters)))
	}
	if b := s.Baseline; b != nil {
		line := fmt.Sprintf("Baseline    %s, %d new flows", b.Status.State, b.Status.New)
		if b.Status.State == "learning" {
			line += ", learning until " + b.Status.LearningUntil.In(now.Location()).Format("Jan 2 15:04")
		}
		if b.Status.New > 0 {
			line = stMedium.Render(line)
		}
		out = append(out, line)
	}
	if c := s.Captures; c != nil {
		line := "Captures    off"
		if c.Enabled {
			line = fmt.Sprintf("Captures    on, buffer %s, %d saved", humanBytes(c.BufferBytes), len(c.Captures))
			if c.KernelDrops > 0 {
				line += stHigh.Render(fmt.Sprintf(", %d kernel drops", c.KernelDrops))
			}
		}
		out = append(out, line)
	}
	if a := s.Advisories; a != nil {
		line := "Advisories  no bundle loaded"
		switch {
		case a.Error != "":
			line = stHigh.Render("Advisories  bundle error: " + a.Error)
		case a.Loaded:
			line = fmt.Sprintf("Advisories  %d from %s, %d days old", a.Advisories, a.Source, a.AgeDays)
			if a.Stale {
				line = stMedium.Render(line + " (stale)")
			}
		}
		out = append(out, line)
	}
	return out
}

// --- Devices ---

var deviceSorts = []string{"last seen", "IP", "TCP", "vendor"}

func (m model) deviceRows() []models.DeviceInfo {
	f := strings.ToLower(m.filter[viewDevices])
	var out []models.DeviceInfo
	for _, d := range m.snap.Devices {
		if f == "" || strings.Contains(strings.ToLower(d.IP+" "+d.MAC+" "+d.Vendor+" "+d.Interface+" "+d.Zone), f) {
			out = append(out, d)
		}
	}
	switch m.sortCol[viewDevices] % len(deviceSorts) {
	case 0:
		slices.SortStableFunc(out, func(a, b models.DeviceInfo) int { return b.LastSeen.Compare(a.LastSeen) })
	case 1:
		slices.SortStableFunc(out, func(a, b models.DeviceInfo) int { return cmpIP(a.IP, b.IP) })
	case 2:
		slices.SortStableFunc(out, func(a, b models.DeviceInfo) int { return cmp.Compare(b.TCPConnections, a.TCPConnections) })
	case 3:
		slices.SortStableFunc(out, func(a, b models.DeviceInfo) int { return cmp.Compare(a.Vendor, b.Vendor) })
	}
	return out
}

func (m model) devicesView(w, h int) []string {
	rows := m.deviceRows()
	now := m.now()
	t := table{cols: []column{{"IP", 15, 0}, {"MAC", 17, 2}, {"Vendor", 0, 0}, {"If", 6, 6}, {"TCP", 6, 0}, {"UDP", 6, 1}, {"DNS", 6, 3}, {"HTTP", 6, 5}, {"TLS", 6, 4}, {"GW", 2, 7}, {"Seen", 5, 0}},
		selected: m.sel[viewDevices], height: h - 3}
	for _, d := range rows {
		gw := ""
		if d.IsGateway {
			gw = "✓"
		}
		t.rows = append(t.rows, []string{d.IP, d.MAC, orDash(d.Vendor), orDash(d.Interface), humanInt(d.TCPConnections), humanInt(d.UDPConnections),
			humanInt(d.DNSQueries), humanInt(d.HTTPRequests), humanInt(d.TLSConnections), gw, ago(d.LastSeen, now)})
	}
	head := fmt.Sprintf("%d devices, sorted by %s", len(rows), deviceSorts[m.sortCol[viewDevices]%len(deviceSorts)])
	return append([]string{stDim.Render(head)}, t.render(w)...)
}

func (m model) deviceDetail(w, h int) []string {
	var d *models.DeviceInfo
	for i := range m.snap.Devices {
		if m.snap.Devices[i].MAC == m.advMAC {
			d = &m.snap.Devices[i]
		}
	}
	if d == nil {
		return []string{"This device is no longer tracked. Press esc."}
	}
	now := m.now()
	out := []string{section(d.IP) + "  " + d.MAC + "  " + orDash(d.Vendor) + stDim.Render("  esc back")}
	facts := fmt.Sprintf("Interface %s, first seen %s ago, last seen %s ago", orDash(d.Interface), ago(d.FirstSeen, now), ago(d.LastSeen, now))
	if d.Zone != "" {
		facts += ", zone " + d.Zone
	}
	if d.IsGateway {
		facts += ", routes traffic (gateway)"
	}
	out = append(out, facts)
	for _, a := range m.snap.Assets {
		if a.MAC == d.MAC {
			role := roleLabel(a.Role)
			if a.RoleSource == "override" {
				role += " (set by an operator)"
			}
			out = append(out, "Role "+role+", protocols "+orDash(strings.Join(a.Protocols, ", ")))
		}
	}
	if d.Asset != nil {
		id := d.Asset
		out = append(out, fmt.Sprintf("Reports itself as %s %s, firmware %s, serial %s (from %s)", orDash(id.Vendor), orDash(id.Model),
			orDash(id.Firmware), orDash(id.Serial), id.Source))
	}
	out = append(out, fmt.Sprintf("TCP %d  UDP %d  ICMP %d  DNS %d  HTTP %d  TLS %d  requests %d  replies %d", d.TCPConnections, d.UDPConnections,
		d.ICMPPackets, d.DNSQueries, d.HTTPRequests, d.TLSConnections, d.RequestCount, d.ReplyCount))

	cw := w
	if w >= 100 {
		cw = w/2 - 1
	}
	var left, right []string
	left = append(left, "", section("Services"))
	left = append(left, barChart(d.Services, 6, cw)...)
	tt := map[string]int{}
	for k, v := range d.TrafficTypeCounts {
		tt[string(k)] = v
	}
	left = append(left, "", section("Traffic types"))
	left = append(left, barChart(tt, 6, cw)...)
	if len(d.DNSDomains) > 0 {
		left = append(left, "", section("DNS queries"))
		left = append(left, barChart(d.DNSDomains, 5, cw)...)
	}
	if len(d.TLSSNIs) > 0 {
		right = append(right, "", section("TLS server names"))
		right = append(right, barChart(d.TLSSNIs, 5, cw)...)
	}
	if len(d.HTTPHosts) > 0 {
		right = append(right, "", section("HTTP hosts"))
		right = append(right, barChart(d.HTTPHosts, 5, cw)...)
	}
	for _, proto := range sortedKeys(d.Industrial) {
		st := d.Industrial[proto]
		right = append(right, "", section(strings.ToUpper(proto))+fmt.Sprintf("  %d requests, %d responses, %d exceptions", st.Requests, st.Responses, st.Exceptions))
		right = append(right, barChart(st.Operations, 5, cw)...)
		if len(st.Peers) > 0 {
			right = append(right, "peers: "+strings.Join(st.Peers, ", "))
		}
	}
	right = append(right, "", section("Advisories"))
	switch {
	case m.advErr != nil:
		right = append(right, "could not load: "+friendlyErr(m.advErr))
	case len(m.adv) == 0:
		right = append(right, stDim.Render("none matched"))
	default:
		for _, a := range m.adv {
			right = append(right, fmt.Sprintf("%s %4.1f %s %s", severityStyle(a.Severity).Render(pad(a.Severity, 8)), a.Score, a.ID, a.Title))
			right = append(right, stDim.Render("   "+a.Product+", "+a.Affected+" ("+a.Confidence+")"))
		}
	}
	return append(out, columns(w, left, right)...)
}

// --- Alerts ---

func (m model) alertRows() []models.AlertEvent {
	f := strings.ToLower(m.filter[viewAlerts])
	var out []models.AlertEvent
	for _, a := range m.snap.Alerts {
		text := a.Rule + " " + a.Severity + " " + a.DeviceIP + " " + a.DeviceMAC + " " + a.Message + " " + a.AckedBy
		for _, t := range a.Techniques {
			text += " " + t.ID + " " + t.Name
		}
		if f == "" || strings.Contains(strings.ToLower(text), f) {
			out = append(out, a)
		}
	}
	slices.SortStableFunc(out, func(x, y models.AlertEvent) int { return y.ObservedAt.Compare(x.ObservedAt) })
	return out
}

func (m model) alertsView(w, h int) []string {
	rows := m.alertRows()
	now := m.now()
	t := table{cols: []column{{"Time", 11, 0}, {"Severity", 8, 0}, {"Rule", 22, 0}, {"Device", 15, 1}, {"Message", 0, 0}, {"ATT&CK", 11, 2}, {"Ack", 10, 3}},
		selected: m.sel[viewAlerts], height: h - 3}
	for _, a := range rows {
		var tech []string
		for _, x := range a.Techniques {
			tech = append(tech, x.ID)
		}
		ack := ""
		if a.AckedBy != "" {
			ack = "✓ " + a.AckedBy
		}
		t.rows = append(t.rows, []string{clock(a.ObservedAt, now), severityStyle(a.Severity).Render(a.Severity), a.Rule, orDash(a.DeviceIP),
			a.Message, strings.Join(tech, ","), ack})
	}
	return append([]string{stDim.Render(fmt.Sprintf("%d rule alerts, newest first", len(rows)))}, t.render(w)...)
}

func (m model) alertDetail(w int) []string {
	a, ok := m.selectedAlert()
	if !ok {
		return []string{"No alert selected. Press esc."}
	}
	now := m.now()
	out := []string{
		section(a.Rule) + "  " + severityStyle(a.Severity).Render(a.Severity) + stDim.Render("  esc back"),
		"Seen " + a.ObservedAt.In(now.Location()).Format("2006-01-02 15:04:05") + " (" + ago(a.ObservedAt, now) + " ago)",
		"Device " + orDash(a.DeviceIP) + "  " + a.DeviceMAC + "  " + orDash(a.Vendor), "",
	}
	out = append(out, wrap(a.Message, w)...)
	if len(a.Techniques) > 0 {
		out = append(out, "", section("ATT&CK for ICS"))
		for _, t := range a.Techniques {
			out = append(out, "  "+t.ID+"  "+t.Name+stDim.Render("  https://attack.mitre.org/techniques/"+t.ID+"/"))
		}
	}
	if a.CaptureID != "" {
		out = append(out, "", "Packet capture "+a.CaptureID+stDim.Render(" (download it from the Control Room or the API)"))
	}
	out = append(out, "")
	if a.AckedBy != "" {
		line := "Acknowledged by " + a.AckedBy
		if a.AckedAt != nil {
			line += " at " + a.AckedAt.In(now.Location()).Format("2006-01-02 15:04")
		}
		out = append(out, stOK.Render(line))
		if a.Note != "" {
			out = append(out, wrap("Note: "+a.Note, w)...)
		}
	} else if m.can("analyst") {
		out = append(out, "Not acknowledged. Press a to acknowledge it.")
	} else {
		out = append(out, "Not acknowledged.")
	}
	return out
}

// wrap breaks s into lines of at most w columns at spaces.
func wrap(s string, w int) []string {
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && ansi.StringWidth(line)+1+ansi.StringWidth(word) > w {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// --- Anomalies ---

func (m model) anomaliesView(w, h int) []string {
	a := m.snap.Anomalies
	if a == nil {
		return []string{"No anomaly data yet."}
	}
	now := m.now()
	state := a.Status
	if a.IsAnomaly {
		state = stHigh.Render("ANOMALY")
	}
	out := []string{
		section("Anomaly model") + fmt.Sprintf("  %s, score %.2f, robust z %.2f, centroid distance %.2f", state, a.CurrentScore, a.RobustZScore, a.CentroidDistance),
		stDim.Render(fmt.Sprintf("%d-second windows, %d in the baseline, last evaluated %s ago, %d recent anomalies",
			a.WindowSeconds, a.BaselineWindows, ago(a.LastEvaluatedAt, now), a.RecentAnomalyCount)),
	}
	if slices.Max(append(m.score.last(w), 0)) == 0 {
		out = append(out, stDim.Render("Score has been 0 since this console started."))
	} else {
		for _, r := range areaChart(m.score.last(w), w, 5) {
			out = append(out, stChart.Render(r))
		}
	}
	if a.LastSummary != "" {
		out = append(out, "")
		out = append(out, wrap(a.LastSummary, w)...)
	}
	f := a.LastFeatures
	out = append(out, "", section("Last window"),
		fmt.Sprintf("packets %.1f/s  DNS %.1f/s  HTTP %.1f/s  TLS %.1f/s  SYN %.1f/s  devices %.0f  unusual ports %.0f  port entropy %.2f",
			f.PacketRate, f.DNSRate, f.HTTPRate, f.TLSRate, f.TCPSynRate, f.UniqueDeviceCount, f.UnusualPortCount, f.PortEntropy))
	if len(a.LastContributions) > 0 {
		t := table{cols: []column{{"What changed", 0, 0}, {"Now", 10, 0}, {"Usual", 10, 0}, {"Robust z", 9, 0}}, selected: -1, height: 6}
		for _, c := range a.LastContributions {
			t.rows = append(t.rows, []string{orDash(c.Label), fmt.Sprintf("%.2f", c.Value), fmt.Sprintf("%.2f", c.BaselineMedian), fmt.Sprintf("%.2f", c.RobustZ)})
		}
		out = append(out, "")
		out = append(out, t.render(w)...)
	}
	if len(a.RecentAlerts) > 0 {
		out = append(out, "", section("Recent anomalies"))
		alerts := slices.Clone(a.RecentAlerts)
		slices.SortFunc(alerts, func(x, y models.AnomalyAlert) int { return y.ObservedAt.Compare(x.ObservedAt) })
		for _, al := range alerts[:min(len(alerts), max(1, h-len(out)-1))] {
			out = append(out, fmt.Sprintf("%s  %s  %5.2f  %s", clock(al.ObservedAt, now), severityStyle(al.Severity).Render(pad(al.Severity, 6)), al.Score, al.Summary))
		}
	}
	return out
}

// --- Assets ---

var assetSorts = []string{"IP", "role", "advisories", "last seen"}

func (m model) assetRows() []asset {
	f := strings.ToLower(m.filter[viewAssets])
	var out []asset
	for _, a := range m.snap.Assets {
		text := a.IP + " " + a.MAC + " " + a.OUIVendor + " " + a.Role + " " + strings.Join(a.Protocols, " ")
		if a.Asset != nil {
			text += " " + a.Asset.Vendor + " " + a.Asset.Model + " " + a.Asset.Firmware
		}
		if f == "" || strings.Contains(strings.ToLower(text), f) {
			out = append(out, a)
		}
	}
	switch m.sortCol[viewAssets] % len(assetSorts) {
	case 0:
		slices.SortStableFunc(out, func(a, b asset) int { return cmpIP(a.IP, b.IP) })
	case 1:
		slices.SortStableFunc(out, func(a, b asset) int { return cmp.Compare(a.Role, b.Role) })
	case 2:
		slices.SortStableFunc(out, func(a, b asset) int { return cmp.Compare(b.Advisories, a.Advisories) })
	case 3:
		slices.SortStableFunc(out, func(a, b asset) int { return b.LastSeen.Compare(a.LastSeen) })
	}
	return out
}

func (m model) assetsView(w, h int) []string {
	rows := m.assetRows()
	now := m.now()
	t := table{cols: []column{{"IP", 15, 0}, {"MAC", 17, 4}, {"Vendor", 0, 0}, {"Model", 14, 2}, {"Firmware", 10, 3}, {"Role", 17, 0}, {"Protocols", 14, 5}, {"Advisories", 12, 1}, {"Seen", 5, 6}},
		selected: m.sel[viewAssets], height: h - 4}
	for _, a := range rows {
		vendor, model, fw := a.OUIVendor, "", ""
		if a.Asset != nil {
			if a.Asset.Vendor != "" {
				vendor = a.Asset.Vendor
			}
			model, fw = a.Asset.Model, a.Asset.Firmware
		}
		role := roleLabel(a.Role)
		if a.RoleSource == "override" {
			role += "*"
		}
		adv := "-"
		if a.Advisories > 0 {
			adv = severityStyle(a.AdvisorySeverity).Render(fmt.Sprintf("%d %s", a.Advisories, a.AdvisorySeverity))
		}
		t.rows = append(t.rows, []string{a.IP, a.MAC, orDash(vendor), orDash(model), orDash(fw), role, orDash(strings.Join(a.Protocols, ",")), adv, ago(a.LastSeen, now)})
	}
	head := fmt.Sprintf("%d industrial assets, sorted by %s. * role set by an operator", len(rows), assetSorts[m.sortCol[viewAssets]%len(assetSorts)])
	out := []string{stDim.Render(head)}
	if a := m.snap.Advisories; a != nil && !a.Loaded {
		out = append(out, stDim.Render("No advisory bundle loaded: build one with tools/advisorygen and set CERBERUS_ADVISORIES_FILE."))
	}
	return append(out, t.render(w)...)
}

var roleLabels = map[string]string{"controller": "Controller", "hmi": "HMI", "scada_server": "SCADA server",
	"engineering_workstation": "Eng. workstation", "gateway": "Gateway", "historian": "Historian", "other": "Other"}

func roleLabel(r string) string {
	if l, ok := roleLabels[r]; ok {
		return l
	}
	return orDash(r)
}

// --- Zones ---

var levelNames = map[int]string{0: "L0 Process", 1: "L1 Basic control", 2: "L2 Supervisory", 3: "L3 Site operations", 4: "L4 Business", 5: "L5 Enterprise"}

func (m model) zonesView(w int) []string {
	z := m.snap.Zones
	if z == nil {
		return []string{"Loading zones…"}
	}
	if len(z.Zones) == 0 {
		return []string{"No zones are set up.", "",
			"Add zones and conduits on the Zones page of the Control Room, or in the segmentation section of the alerts file.",
			"Cerberus then alerts on traffic that crosses a zone boundary without a conduit."}
	}
	names := map[string]string{}
	for _, x := range z.Zones {
		names[x.ID] = x.Name
	}
	zs := slices.Clone(z.Zones)
	slices.SortFunc(zs, func(a, b zoneInfo) int { return cmp.Or(cmp.Compare(b.Level, a.Level), cmp.Compare(a.Name, b.Name)) })
	t := table{cols: []column{{"Level", 19, 0}, {"Zone", 20, 0}, {"Ranges", 0, 0}, {"Devices", 7, 0}, {"Industrial", 10, 2}, {"Blocking", 8, 1}}, selected: -1, height: len(zs)}
	for _, x := range zs {
		ind, blk := "", "allowed"
		if x.Industrial {
			ind = "yes"
		}
		if !x.Enforce {
			blk = "refused"
		}
		t.rows = append(t.rows, []string{levelNames[x.Level], x.Name, strings.Join(x.CIDRs, ", "), itoa(x.Devices), ind, blk})
	}
	out := append([]string{section("Zones")}, t.render(w)...)
	out = append(out, "", section("Conduits"))
	if len(z.Conduits) == 0 {
		out = append(out, stDim.Render("none: all traffic between zones alerts"))
	}
	for _, c := range z.Conduits {
		arrow := "→"
		if c.Bidirectional {
			arrow = "↔"
		}
		ports := "any port"
		if len(c.Ports) > 0 {
			ps := make([]string, len(c.Ports))
			for i, p := range c.Ports {
				ps[i] = itoa(p)
			}
			ports = "ports " + strings.Join(ps, ", ")
		}
		out = append(out, fmt.Sprintf("  %s %s %s  %s", orDash(names[c.From]), arrow, orDash(names[c.To]), ports))
	}
	out = append(out, "", section("Traffic with no conduit"))
	if len(z.Violations) == 0 {
		out = append(out, stOK.Render("none seen"))
	} else {
		v := map[string]int{}
		for k, n := range z.Violations {
			from, to, _ := strings.Cut(k, ">")
			v[orDash(names[from])+" → "+orDash(names[to])] = n
		}
		out = append(out, barChart(v, 8, w)...)
	}
	return out
}

// --- Baseline ---

func (m model) flowRows() []baselineFlow {
	b := m.snap.Baseline
	if b == nil {
		return nil
	}
	f := strings.ToLower(m.filter[viewBaseline])
	var out []baselineFlow
	for _, x := range b.Flows {
		if f == "" || strings.Contains(strings.ToLower(x.Client+" "+x.Server+" "+x.Protocol+" "+x.Class+" "+x.Status), f) {
			out = append(out, x)
		}
	}
	rank := map[string]int{"new": 0, "learned": 1, "approved": 2}
	slices.SortStableFunc(out, func(a, b baselineFlow) int {
		return cmp.Or(cmp.Compare(rank[a.Status], rank[b.Status]), b.LastSeen.Compare(a.LastSeen))
	})
	return out
}

func (m model) baselineView(w, h int) []string {
	b := m.snap.Baseline
	if b == nil {
		return []string{"Loading the flow baseline…"}
	}
	st := b.Status
	now := m.now()
	head := fmt.Sprintf("%s: %d learned, %d approved, %d new", st.State, st.Learned, st.Approved, st.New)
	switch st.State {
	case "learning":
		head += ", learning until " + st.LearningUntil.In(now.Location()).Format("2006-01-02 15:04")
	case "disabled":
		return []string{"The flow baseline is turned off in the alerts config."}
	}
	if st.Dropped > 0 {
		head += stMedium.Render(fmt.Sprintf(", %d flows not recorded (limit %d)", st.Dropped, st.MaxFlows))
	}
	rows := m.flowRows()
	t := table{cols: []column{{"Status", 10, 0}, {"Client", 0, 0}, {"Server", 0, 0}, {"Protocol", 9, 0}, {"Class", 10, 0}, {"Count", 7, 1}, {"Last seen", 9, 2}},
		selected: m.sel[viewBaseline], height: h - 3, marked: map[int]bool{}}
	for i, f := range rows {
		status := f.Status
		if status == "new" {
			status = stMedium.Render("new")
		}
		t.rows = append(t.rows, []string{status, f.Client, f.Server, f.Protocol, f.Class, humanInt(f.Count), ago(f.LastSeen, now)})
		if m.marked[f.ID] {
			t.marked[i] = true
		}
	}
	return append([]string{section("Flow baseline") + "  " + head}, t.render(w)...)
}

// --- Policy ---

func (m model) policyView(w, h int) []string {
	p := m.snap.Policy
	if p == nil {
		return []string{"The policy engine is not enabled on this sensor."}
	}
	now := m.now()
	mode := "dry run: rules are counted, nothing is dropped"
	if p.Mode == "enforce" {
		mode = stHigh.Render("enforcing: matching packets are dropped")
	}
	kernel := stOK.Render("attached")
	if !p.KernelAttached {
		kernel = stMedium.Render("not attached")
	}
	out := []string{section("Policy") + "  " + mode + ", kernel " + kernel, ""}
	rt := table{cols: []column{{"Rule", 0, 0}, {"Target", 0, 0}, {"Action", 6, 0}, {"Direction", 9, 2}, {"Packets", 9, 0}, {"Bytes", 9, 1}}, selected: -1, height: max(2, h/3)}
	for _, r := range p.Rules {
		target := r.CIDR
		switch {
		case r.Hostname != "":
			target = orDash(r.HostMatch) + " " + r.Hostname
		case r.MAC != "":
			target = "MAC " + r.MAC
		}
		rt.rows = append(rt.rows, []string{r.ID, target, r.Action, orDash(r.Direction), humanCount(float64(r.Counters.Packets)), humanSize(float64(r.Counters.Bytes))})
	}
	out = append(out, stBold.Render(fmt.Sprintf("Block rules (%d of %d)", len(p.Rules), p.MaxRules)))
	out = append(out, rt.render(w)...)
	ft := table{cols: []column{{"Filter", 14, 0}, {"Matches", 0, 0}, {"Verdict", 8, 0}, {"On", 3, 0}, {"Packets", 9, 0}}, selected: -1, height: max(2, h/4)}
	for _, f := range p.Filters {
		on := "✓"
		if !f.Enabled {
			on = ""
		}
		ft.rows = append(ft.rows, []string{f.ID, f.Summary, f.Verdict, on, humanCount(float64(f.Counters.Packets))})
	}
	out = append(out, "", stBold.Render(fmt.Sprintf("Filters (%d of %d)", len(p.Filters), p.MaxFilters)))
	out = append(out, ft.render(w)...)
	out = append(out, "", stBold.Render("Recent changes"))
	audit := slices.Clone(p.Audit)
	slices.SortFunc(audit, func(a, b auditEntry) int { return b.At.Compare(a.At) })
	if len(audit) == 0 {
		out = append(out, stDim.Render("none"))
	}
	for _, a := range audit[:min(len(audit), max(1, h-len(out)))] {
		out = append(out, fmt.Sprintf("%s  %-24s %-14s %s %s", clock(a.At, now), clip(a.Actor, 24), a.Action, a.RuleID, a.Detail))
	}
	out = append(out, stDim.Render("Change policy from the Control Room or the API."))
	return out
}

// --- Captures ---

func (m model) captureRows() []captureEntry {
	c := m.snap.Captures
	if c == nil {
		return nil
	}
	f := strings.ToLower(m.filter[viewCaptures])
	var out []captureEntry
	for _, x := range c.Captures {
		if f == "" || strings.Contains(strings.ToLower(x.ID+" "+x.Reason+" "+x.Rule+" "+x.Address), f) {
			out = append(out, x)
		}
	}
	slices.SortStableFunc(out, func(a, b captureEntry) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out
}

func (m model) capturesView(w, h int) []string {
	c := m.snap.Captures
	if c == nil || !c.Enabled {
		return []string{"Packet capture is turned off.", "", "Enable it in the capture section of the alerts file to keep recent frames and save them around alerts."}
	}
	now := m.now()
	head := fmt.Sprintf("Buffer %s, %d frames on %s; %d pending, %d skipped", humanBytes(c.BufferBytes), c.BufferPackets,
		orDash(strings.Join(c.Interfaces, ", ")), c.Pending, c.Skipped)
	if c.KernelDrops > 0 {
		head += stHigh.Render(fmt.Sprintf("; %d frames dropped by the kernel", c.KernelDrops))
	}
	rows := m.captureRows()
	t := table{cols: []column{{"Saved", 11, 0}, {"Reason", 6, 3}, {"Rule", 0, 0}, {"Address", 0, 0}, {"Span", 6, 4}, {"Packets", 8, 2}, {"Size", 9, 1}, {"Complete", 16, 0}},
		selected: m.sel[viewCaptures], height: h - 4}
	for _, x := range rows {
		complete := stOK.Render("yes")
		if x.Drops > 0 {
			complete = stMedium.Render(fmt.Sprintf("no, %d dropped", x.Drops))
		}
		t.rows = append(t.rows, []string{clock(x.CreatedAt, now), x.Reason, orDash(x.Rule), orDash(x.Address), x.To.Sub(x.From).Round(time.Second).String(),
			humanInt(x.Packets), humanBytes(x.Bytes), complete})
	}
	out := []string{section("Captures") + "  " + head}
	out = append(out, t.render(w)...)
	return append(out, stDim.Render("Captures hold full packets; download them from the Control Room or the API (admin)."))
}

// --- DNS / TLS ---

func (m model) dnsView(w int) []string {
	s := m.snap.Summary
	if s == nil {
		return []string{"Loading…"}
	}
	cw := w
	if w >= 100 {
		cw = w/2 - 1
	}
	block := func(title string, data map[string]int, n int) []string {
		return append([]string{section(title)}, append(barChart(data, n, cw), "")...)
	}
	var left, right []string
	left = append(left, block("DNS query types", s.DNSQueryTypes, 5)...)
	left = append(left, block("DNS response codes", s.DNSResponseCodes, 5)...)
	left = append(left, block("Top answered domains", s.DNSResponseDomains, 8)...)
	right = append(right, block("Connections after a DNS lookup", s.DNSCorrelatedDomains, 6)...)
	right = append(right, block("Encrypted DNS", s.EncryptedDNS, 4)...)
	right = append(right, block("TLS versions", s.TLSVersions, 5)...)
	right = append(right, block("Top TLS server names", s.TopTLSSNIs, 8)...)
	return columns(w, left, right)
}

// --- helpers ---

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// cmpIP orders dotted IPv4 addresses numerically, others as text.
func cmpIP(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) == 4 && len(pb) == 4 {
		for i := range 4 {
			if c := cmp.Compare(atoiSafe(pa[i]), atoiSafe(pb[i])); c != 0 {
				return c
			}
		}
		return 0
	}
	return cmp.Compare(a, b)
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}
