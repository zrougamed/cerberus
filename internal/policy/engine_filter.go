package policy

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// FilterStatus is a filter rule with its position and kernel counters.
type FilterStatus struct {
	FilterRule
	Position int     `json:"position"`
	Summary  string  `json:"summary"`
	Counters Counter `json:"counters"`
}

type filterEntry struct {
	rule FilterRule
	c    compiledMatch
	slot uint32
}

const (
	maxLogs                = 500
	defaultLogEverySeconds = 1.0
	maxLogEverySeconds     = 3600.0
)

func (e *Engine) idTakenLocked(id string) bool {
	_, isRule := e.rules[id]
	return isRule || e.filterIndexLocked(id) >= 0
}

func (e *Engine) filterIndexLocked(id string) int {
	return slices.IndexFunc(e.filters, func(f *filterEntry) bool { return f.rule.ID == id })
}

func (e *Engine) freeFilterSlotLocked() (uint32, bool) {
	for i, used := range e.filterSlots {
		if !used {
			return uint32(i), true
		}
	}
	return 0, false
}

// chainLocked is the kernel image of the enabled filters, in order.
func (e *Engine) chainLocked() []filterValue {
	out := make([]filterValue, 0, len(e.filters))
	for _, f := range e.filters {
		if f.rule.Enabled {
			out = append(out, encodeFilter(f.rule, f.c, f.slot))
		}
	}
	return out
}

func (e *Engine) syncChainLocked() error {
	if e.kernel == nil {
		return nil
	}
	if err := e.kernel.WriteChain(e.chainLocked()); err != nil {
		return fmt.Errorf("write filter chain: %w", err)
	}
	return nil
}

// loadFilterLocked adds a stored filter (from the state file) at the end.
func (e *Engine) loadFilterLocked(f FilterRule) error {
	if !ruleIDPattern.MatchString(f.ID) {
		return fmt.Errorf("bad id %q", f.ID)
	}
	if e.idTakenLocked(f.ID) {
		return fmt.Errorf("%w: id %q exists", ErrConflict, f.ID)
	}
	v, err := normalizeVerdict(f.Verdict)
	if err != nil {
		return err
	}
	f.Verdict = v
	c, err := compileMatch(f.Match, false)
	if err != nil {
		return err
	}
	slot, ok := e.freeFilterSlotLocked()
	if !ok {
		return fmt.Errorf("%w (%d filter rules)", ErrFull, MaxFilterRules)
	}
	e.filterSlots[slot] = true
	e.filters = append(e.filters, &filterEntry{rule: f, c: c, slot: slot})
	return nil
}

func (e *Engine) protectedFilterHit(c compiledMatch) string {
	for _, a := range e.opts.Protected {
		a = a.Unmap()
		if c.src.IsValid() && !c.srcNot && c.src.Contains(a) {
			return a.String()
		}
		if c.dst.IsValid() && !c.dstNot && c.dst.Contains(a) {
			return a.String()
		}
	}
	for _, m := range e.opts.ProtectedMAC {
		if c.mac != nil && slices.Equal(c.mac, m) {
			return m.String()
		}
	}
	return ""
}

// AddFilter validates and inserts a filter rule into the chain.
func (e *Engine) AddFilter(in FilterInput, actor string) (FilterRule, error) {
	r, c, err := normalizeFilter(in)
	if err != nil {
		return FilterRule{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if r.Verdict == VerdictDrop && !in.Force {
		if !c.hasAddress {
			return FilterRule{}, fmt.Errorf("%w: a drop rule without src, dst or src_mac affects every host, this one included; set force to confirm", ErrProtected)
		}
		if p := e.protectedFilterHit(c); p != "" {
			return FilterRule{}, fmt.Errorf("%w (%s); set force to override", ErrProtected, p)
		}
	}
	if r.ID == "" {
		for r.ID = newRuleID(); e.idTakenLocked(r.ID); r.ID = newRuleID() {
		}
	} else if e.idTakenLocked(r.ID) {
		return FilterRule{}, fmt.Errorf("%w: id %q exists", ErrConflict, r.ID)
	}
	slot, ok := e.freeFilterSlotLocked()
	if !ok {
		return FilterRule{}, fmt.Errorf("%w (%d filter rules)", ErrFull, MaxFilterRules)
	}
	now := e.opts.Now().UTC()
	r.CreatedAt, r.CreatedBy = now, actor
	if in.TTLSeconds > 0 {
		exp := now.Add(time.Duration(in.TTLSeconds) * time.Second)
		r.ExpiresAt = &exp
	}

	pos := len(e.filters)
	if in.Position != nil {
		if *in.Position < 0 || *in.Position > len(e.filters) {
			return FilterRule{}, fmt.Errorf("%w: position %d out of range 0-%d", ErrInvalid, *in.Position, len(e.filters))
		}
		pos = *in.Position
	}
	prev := slices.Clone(e.filters)
	e.filters = slices.Insert(e.filters, pos, &filterEntry{rule: r, c: c, slot: slot})
	e.filterSlots[slot] = true

	if e.kernel != nil {
		if err := e.kernel.ResetFilterCounter(slot); err != nil {
			e.filters, e.filterSlots[slot] = prev, false
			return FilterRule{}, fmt.Errorf("install filter in kernel: %w", err)
		}
	}
	if err := e.commitFilterChangeLocked(prev); err != nil {
		e.filterSlots[slot] = false
		return FilterRule{}, err
	}
	e.auditLocked(actor, "add-filter", r.ID, fmt.Sprintf("Added filter at position %d: %s", pos+1, describeFilter(r)))
	return r, nil
}

// commitFilterChangeLocked pushes the chain and saves the policy; on failure
// it restores prev in memory and in the kernel.
func (e *Engine) commitFilterChangeLocked(prev []*filterEntry) error {
	if err := e.syncChainLocked(); err != nil {
		e.filters = prev
		_ = e.syncChainLocked()
		return err
	}
	if err := e.saveLocked(); err != nil {
		e.filters = prev
		_ = e.syncChainLocked()
		return err
	}
	return nil
}

// RemoveFilter deletes a filter rule.
func (e *Engine) RemoveFilter(id, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.removeFilterLocked(id, actor, "remove-filter")
}

func (e *Engine) removeFilterLocked(id, actor, action string) error {
	i := e.filterIndexLocked(id)
	if i < 0 {
		return ErrNotFound
	}
	f := e.filters[i]
	prev := slices.Clone(e.filters)
	e.filters = slices.Delete(slices.Clone(e.filters), i, i+1)
	if err := e.commitFilterChangeLocked(prev); err != nil {
		return err
	}
	e.filterSlots[f.slot] = false
	delete(e.lastPackets, id)
	delete(e.lastReport, id)
	verb := "Removed filter: "
	if action == "expire" {
		verb = "Expired filter: "
	}
	e.auditLocked(actor, action, id, verb+describeFilter(f.rule))
	return nil
}

// MoveFilter moves a filter rule to a 0-based position in the chain.
func (e *Engine) MoveFilter(id string, position int, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := e.filterIndexLocked(id)
	if i < 0 {
		return ErrNotFound
	}
	if position < 0 || position >= len(e.filters) {
		return fmt.Errorf("%w: position %d out of range 0-%d", ErrInvalid, position, len(e.filters)-1)
	}
	if position == i {
		return nil
	}
	prev := slices.Clone(e.filters)
	f := e.filters[i]
	next := slices.Delete(slices.Clone(e.filters), i, i+1)
	e.filters = slices.Insert(next, position, f)
	if err := e.commitFilterChangeLocked(prev); err != nil {
		return err
	}
	e.auditLocked(actor, "move-filter", id, fmt.Sprintf("Moved filter from position %d to %d", i+1, position+1))
	return nil
}

// SetFilterEnabled switches a filter rule on or off without removing it.
func (e *Engine) SetFilterEnabled(id string, enabled bool, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := e.filterIndexLocked(id)
	if i < 0 {
		return ErrNotFound
	}
	if e.filters[i].rule.Enabled == enabled {
		return nil
	}
	prev := slices.Clone(e.filters)
	updated := *e.filters[i]
	updated.rule.Enabled = enabled
	e.filters = slices.Clone(e.filters)
	e.filters[i] = &updated
	if err := e.commitFilterChangeLocked(prev); err != nil {
		return err
	}
	state := "Disabled"
	if enabled {
		state = "Enabled"
	}
	e.auditLocked(actor, "toggle-filter", id, state+" filter: "+describeFilter(updated.rule))
	return nil
}

// RecordLog decodes one filter_log ring buffer record.
func (e *Engine) RecordLog(raw []byte) error {
	ev, err := decodeLogEvent(raw)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	id := fmt.Sprintf("slot-%d", ev.Slot)
	for _, f := range e.filters {
		if f.slot == ev.Slot {
			id = f.rule.ID
			break
		}
	}
	e.logs = append(e.logs, ev.entry(e.opts.Now().UTC(), id))
	if len(e.logs) > maxLogs {
		e.logs = slices.Clone(e.logs[len(e.logs)-maxLogs:])
	}
	return nil
}

// Logs returns up to limit log entries, newest first.
func (e *Engine) Logs(limit int) []FilterLogEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 || limit > len(e.logs) {
		limit = len(e.logs)
	}
	out := make([]FilterLogEntry, 0, limit)
	for i := len(e.logs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.logs[i])
	}
	return out
}

func normalizeFilter(in FilterInput) (FilterRule, compiledMatch, error) {
	r := FilterRule{
		ID:      strings.TrimSpace(in.ID),
		Enabled: !in.Disabled,
		Match:   in.Match,
		Log:     in.Log,
		Comment: strings.TrimSpace(in.Comment),
	}
	if r.ID != "" && !ruleIDPattern.MatchString(r.ID) {
		return r, compiledMatch{}, fmt.Errorf("id %q: use 1-64 letters, digits, '_' or '-'", r.ID)
	}
	v, err := normalizeVerdict(in.Verdict)
	if err != nil {
		return r, compiledMatch{}, err
	}
	r.Verdict = v
	if len(r.Comment) > maxCommentLen {
		return r, compiledMatch{}, fmt.Errorf("comment longer than %d bytes", maxCommentLen)
	}
	if in.TTLSeconds < 0 || in.TTLSeconds > maxTTL {
		return r, compiledMatch{}, fmt.Errorf("ttl_seconds must be between 0 and %d", maxTTL)
	}
	if r.Log {
		r.LogEverySeconds = defaultLogEverySeconds
		if in.LogEverySeconds != nil {
			s := *in.LogEverySeconds
			if s < 0 || s > maxLogEverySeconds || math.IsNaN(s) {
				return r, compiledMatch{}, fmt.Errorf("log_every_seconds must be between 0 and %.0f", maxLogEverySeconds)
			}
			r.LogEverySeconds = s
		}
	}
	c, err := compileMatch(in.Match, true)
	if err != nil {
		return r, compiledMatch{}, err
	}
	r.Match = canonicalMatch(in.Match, c)
	return r, c, nil
}

// canonicalMatch stores normalised forms (masked prefixes, lower-case
// names) so the policy file and console show what is enforced.
func canonicalMatch(m FilterMatch, c compiledMatch) FilterMatch {
	out := m
	out.Interface = c.iface
	out.Family = ""
	switch c.family {
	case 4:
		out.Family = "ipv4"
	case 6:
		out.Family = "ipv6"
	}
	out.Protocol = strings.ToLower(strings.TrimSpace(m.Protocol))
	if c.src.IsValid() {
		out.Src = c.src.String()
	}
	if c.dst.IsValid() {
		out.Dst = c.dst.String()
	}
	if c.mac != nil {
		out.SrcMAC = c.mac.String()
	}
	out.SrcPort = portString(c.sport)
	out.DstPort = portString(c.dport)
	out.SrcNot, out.DstNot = c.srcNot, c.dstNot
	out.SrcPortNot, out.DstPortNot = c.sportNot, c.dportNot
	out.TCPFlagsAny = flagNames(c.tcpAny)
	out.TCPFlagsAll = flagNames(c.tcpAll)
	return out
}

func portString(r [2]uint16) string {
	switch {
	case r[1] == 0:
		return ""
	case r[0] == r[1]:
		return fmt.Sprint(r[0])
	default:
		return fmt.Sprintf("%d-%d", r[0], r[1])
	}
}

func flagNames(bits uint8) []string {
	if bits == 0 {
		return nil
	}
	return strings.Split(tcpFlagString(bits), ",")
}

func describeFilter(r FilterRule) string {
	s := fmt.Sprintf("%s %s", r.Verdict, r.Match.Summary())
	if r.Log {
		s += " (log)"
	}
	if !r.Enabled {
		s += " [disabled]"
	}
	if r.ExpiresAt != nil {
		s += " until " + r.ExpiresAt.Format(time.RFC3339)
	}
	if r.Comment != "" {
		s += ": " + r.Comment
	}
	return s
}
