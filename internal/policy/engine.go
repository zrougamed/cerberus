package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned for an unknown rule id.
var ErrNotFound = errors.New("rule not found")

// ErrConflict is returned when a rule id or target already exists.
var ErrConflict = errors.New("rule conflicts with an existing rule")

// ErrInvalid wraps validation failures of client input.
var ErrInvalid = errors.New("invalid rule")

// ErrFull is returned when all MaxRules slots are in use.
var ErrFull = errors.New("policy is full")

// Options configures an Engine.
type Options struct {
	// StatePath is the JSON file the policy is persisted to. Empty keeps
	// the policy in memory only (tests).
	StatePath string
	// Protected addresses cannot be covered by a rule unless the request
	// sets force: the default gateway and this host's own addresses, so a
	// typo cannot cut the console off the network.
	Protected    []netip.Addr
	ProtectedMAC []net.HardwareAddr
	// WatchOnly maps zone ids to networks where drop rules need force:
	// industrial zones, where a dropped packet can stop a process.
	WatchOnly map[string][]netip.Prefix
	// HitRealert is the minimum gap between two hit reports for one rule.
	HitRealert time.Duration
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
}

// AuditEntry records one change to the policy.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	RuleID string    `json:"rule_id,omitempty"`
	Detail string    `json:"detail"`
}

// RuleStatus is a rule with its kernel counters.
type RuleStatus struct {
	Rule
	Counters Counter `json:"counters"`
}

// Status is a point-in-time view of the policy.
type Status struct {
	Mode           Mode           `json:"mode"`
	KernelAttached bool           `json:"kernel_attached"`
	MaxRules       int            `json:"max_rules"`
	Rules          []RuleStatus   `json:"rules"`
	MaxFilters     int            `json:"max_filters"`
	Filters        []FilterStatus `json:"filters"`
	Audit          []AuditEntry   `json:"audit"`
}

// Hit reports that a rule matched traffic since the previous report.
// Exactly one of Rule (blocklist) and Filter is meaningful.
type Hit struct {
	Rule     Rule
	Filter   *FilterRule
	Delta    Counter // packets/bytes since the last report
	Total    Counter
	Enforced bool // true when the packets were actually dropped
}

type entry struct {
	rule Rule
	t    target
	slot uint32
}

type stateFile struct {
	Version int          `json:"version"`
	Mode    Mode         `json:"mode"`
	Rules   []Rule       `json:"rules"`
	Filters []FilterRule `json:"filters,omitempty"` // in evaluation order
}

const maxAudit = 200

// Engine owns the policy and keeps the kernel maps in sync with it.
type Engine struct {
	mu       sync.Mutex
	opts     Options
	mode     Mode
	rules    map[string]*entry
	byTarget map[string]string
	slots    [MaxRules]bool
	kernel   Kernel
	audit    []AuditEntry

	filters     []*filterEntry // evaluation order
	filterSlots [MaxFilterRules]bool
	logs        []FilterLogEntry // newest last, capped at maxLogs

	lastPackets map[string]uint64
	lastReport  map[string]time.Time
}

// Open loads the persisted policy (if any). It does not touch the kernel
// until Bind. A state file that fails validation is an error: a security
// policy must not silently disappear.
func Open(opts Options) (*Engine, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HitRealert <= 0 {
		opts.HitRealert = 10 * time.Minute
	}
	e := &Engine{
		opts:        opts,
		mode:        ModeMonitor,
		rules:       make(map[string]*entry),
		byTarget:    make(map[string]string),
		lastPackets: make(map[string]uint64),
		lastReport:  make(map[string]time.Time),
	}
	if opts.StatePath == "" {
		return e, nil
	}
	data, err := os.ReadFile(opts.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", opts.StatePath, err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", opts.StatePath, err)
	}
	switch st.Mode {
	case ModeMonitor, ModeEnforce:
		e.mode = st.Mode
	case "":
	default:
		return nil, fmt.Errorf("policy: %s: unknown mode %q", opts.StatePath, st.Mode)
	}
	now := opts.Now()
	for _, r := range st.Rules {
		if r.ParentID != "" {
			// Legacy or hand-edited derived rules are ignored; SyncHostnames recreates them.
			continue
		}
		if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
			continue
		}
		t, err := targetOf(r)
		if err != nil {
			return nil, fmt.Errorf("policy: %s: rule %q: %w", opts.StatePath, r.ID, err)
		}
		if !ruleIDPattern.MatchString(r.ID) {
			return nil, fmt.Errorf("policy: %s: bad rule id %q", opts.StatePath, r.ID)
		}
		if err := e.insertLocked(r, t); err != nil {
			return nil, fmt.Errorf("policy: %s: rule %q: %w", opts.StatePath, r.ID, err)
		}
	}
	for _, f := range st.Filters {
		if f.ExpiresAt != nil && !now.Before(*f.ExpiresAt) {
			continue
		}
		if err := e.loadFilterLocked(f); err != nil {
			return nil, fmt.Errorf("policy: %s: filter %q: %w", opts.StatePath, f.ID, err)
		}
	}
	return e, nil
}

// insertLocked adds a rule to the in-memory index and assigns a slot.
func (e *Engine) insertLocked(r Rule, t target) error {
	if _, dup := e.rules[r.ID]; dup || e.filterIndexLocked(r.ID) >= 0 {
		return fmt.Errorf("%w: id %q exists", ErrConflict, r.ID)
	}
	if other, dup := e.byTarget[t.key()]; dup {
		return fmt.Errorf("%w: %s is already covered by rule %q", ErrConflict, t.key(), other)
	}
	slot, ok := e.freeSlotLocked()
	if !ok {
		return fmt.Errorf("%w (%d rules)", ErrFull, MaxRules)
	}
	e.slots[slot] = true
	e.rules[r.ID] = &entry{rule: r, t: t, slot: slot}
	e.byTarget[t.key()] = r.ID
	return nil
}

func (e *Engine) freeSlotLocked() (uint32, bool) {
	for i, used := range e.slots {
		if !used {
			return uint32(i), true
		}
	}
	return 0, false
}

func (e *Engine) removeLocked(id string) *entry {
	en := e.rules[id]
	if en == nil {
		return nil
	}
	delete(e.rules, id)
	delete(e.byTarget, en.t.key())
	delete(e.lastPackets, id)
	delete(e.lastReport, id)
	e.slots[en.slot] = false
	return en
}

// Bind attaches the engine to the classifier and pushes the whole policy.
func (e *Engine) Bind(k Kernel) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.rules {
		if en.t.userspaceOnly() {
			continue
		}
		if err := k.ResetCounter(en.slot); err != nil {
			return fmt.Errorf("policy: reset counter: %w", err)
		}
		if err := put(k, en); err != nil {
			return fmt.Errorf("policy: load rule %q: %w", en.rule.ID, err)
		}
	}
	for _, f := range e.filters {
		if err := k.ResetFilterCounter(f.slot); err != nil {
			return fmt.Errorf("policy: reset filter counter: %w", err)
		}
	}
	if err := k.WriteChain(e.chainLocked()); err != nil {
		return fmt.Errorf("policy: load filter chain: %w", err)
	}
	if err := k.SetEnforce(e.mode == ModeEnforce); err != nil {
		return fmt.Errorf("policy: set mode: %w", err)
	}
	e.kernel = k
	return nil
}

func put(k Kernel, en *entry) error {
	if en.t.userspaceOnly() {
		return nil
	}
	v := encode(en.rule, en.slot)
	if en.t.mac != nil {
		return k.PutMAC(en.t.mac, v)
	}
	return k.PutPrefix(en.t.prefix, v)
}

func del(k Kernel, en *entry) error {
	if en.t.userspaceOnly() {
		return nil
	}
	if en.t.mac != nil {
		return k.DeleteMAC(en.t.mac)
	}
	return k.DeletePrefix(en.t.prefix)
}

func (e *Engine) protectedHit(t target) string {
	if t.mac != nil {
		for _, m := range e.opts.ProtectedMAC {
			if slices.Equal(m, t.mac) {
				return m.String()
			}
		}
		return ""
	}
	for _, a := range e.opts.Protected {
		if t.prefix.Contains(a.Unmap()) {
			return a.String()
		}
	}
	return ""
}

// watchOnlyIDs returns the watch-only zone ids sorted, for stable errors.
func (e *Engine) watchOnlyIDs() []string {
	ids := make([]string, 0, len(e.opts.WatchOnly))
	for id := range e.opts.WatchOnly {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// watchOnlyHit names the watch-only zone a prefix overlaps, or "".
func (e *Engine) watchOnlyHit(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	for _, id := range e.watchOnlyIDs() {
		for _, z := range e.opts.WatchOnly[id] {
			if z.Overlaps(p) {
				return fmt.Sprintf("%s (%s)", id, z)
			}
		}
	}
	return ""
}

// watchOnlyFilterHit names a watch-only zone a drop filter can match. A
// negated side ("not in X") matches every address outside X, so it hits a
// zone unless X contains the whole zone.
func (e *Engine) watchOnlyFilterHit(c compiledMatch) string {
	for _, side := range []struct {
		p   netip.Prefix
		not bool
	}{{c.src, c.srcNot}, {c.dst, c.dstNot}} {
		if !side.p.IsValid() {
			continue
		}
		if !side.not {
			if z := e.watchOnlyHit(side.p); z != "" {
				return z
			}
			continue
		}
		for _, id := range e.watchOnlyIDs() {
			for _, z := range e.opts.WatchOnly[id] {
				if side.p.Bits() > z.Bits() || !side.p.Contains(z.Addr()) {
					return fmt.Sprintf("%s (%s)", id, z)
				}
			}
		}
	}
	return ""
}

func newRuleID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}

// Add validates and installs a rule.
func (e *Engine) Add(in RuleInput, actor string) (Rule, error) {
	r, t, err := normalize(in)
	if err != nil {
		return Rule{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if p := e.protectedHit(t); p != "" && !in.Force {
		return Rule{}, fmt.Errorf("%w: it covers %s, which is this host or the gateway; set force to override", ErrProtected, p)
	}
	if r.Action == ActionDrop && t.mac == nil && !t.userspaceOnly() && !in.Force {
		if z := e.watchOnlyHit(t.prefix); z != "" {
			return Rule{}, fmt.Errorf("%w: it overlaps watch-only zone %s; set enforce on the zone or force to override", ErrProtected, z)
		}
	}
	if r.ID == "" {
		for r.ID = newRuleID(); e.idTakenLocked(r.ID); r.ID = newRuleID() {
		}
	}
	now := e.opts.Now().UTC()
	r.CreatedAt, r.CreatedBy = now, actor
	if in.TTLSeconds > 0 {
		exp := now.Add(time.Duration(in.TTLSeconds) * time.Second)
		r.ExpiresAt = &exp
	}
	if err := e.insertLocked(r, t); err != nil {
		return Rule{}, err
	}
	en := e.rules[r.ID]
	if e.kernel != nil {
		err := e.kernel.ResetCounter(en.slot)
		if err == nil {
			err = put(e.kernel, en)
		}
		if err != nil {
			e.removeLocked(r.ID)
			return Rule{}, fmt.Errorf("install rule in kernel: %w", err)
		}
	}
	if err := e.saveLocked(); err != nil {
		if e.kernel != nil {
			_ = del(e.kernel, en)
		}
		e.removeLocked(r.ID)
		return Rule{}, err
	}
	e.auditLocked(actor, "add", r.ID, "Added: "+describe(r))
	return r, nil
}

// Remove deletes a rule.
func (e *Engine) Remove(id, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.removeAndSaveLocked(id, actor, "remove")
}

func (e *Engine) removeAndSaveLocked(id, actor, action string) error {
	en := e.rules[id]
	if en == nil {
		return ErrNotFound
	}
	// Cascade: drop derived MAC quarantines before the parent hostname rule.
	if en.rule.Hostname != "" && en.rule.ParentID == "" {
		for childID, child := range e.rules {
			if child.rule.ParentID != id {
				continue
			}
			if e.kernel != nil {
				if err := del(e.kernel, child); err != nil {
					return fmt.Errorf("remove derived rule from kernel: %w", err)
				}
			}
			e.removeLocked(childID)
		}
	}
	if e.kernel != nil {
		if err := del(e.kernel, en); err != nil {
			return fmt.Errorf("remove rule from kernel: %w", err)
		}
	}
	e.removeLocked(id)
	if err := e.saveLocked(); err != nil {
		// The kernel no longer has the rule; keep memory consistent with it
		// and report that the file is stale.
		e.auditLocked(actor, action, id, "removed, but saving the policy failed: "+err.Error())
		return err
	}
	verb := "Removed: "
	if action == "expire" {
		verb = "Expired: "
	}
	e.auditLocked(actor, action, id, verb+describe(en.rule))
	return nil
}

// SetMode switches between monitor (dry run) and enforce.
func (e *Engine) SetMode(m Mode, actor string) error {
	if m != ModeMonitor && m != ModeEnforce {
		return fmt.Errorf("%w: unknown mode %q (want monitor|enforce)", ErrInvalid, m)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if m == e.mode {
		return nil
	}
	prev := e.mode
	if e.kernel != nil {
		if err := e.kernel.SetEnforce(m == ModeEnforce); err != nil {
			return fmt.Errorf("set mode in kernel: %w", err)
		}
	}
	e.mode = m
	if err := e.saveLocked(); err != nil {
		if e.kernel != nil {
			_ = e.kernel.SetEnforce(prev == ModeEnforce)
		}
		e.mode = prev
		return err
	}
	e.auditLocked(actor, "mode", "", fmt.Sprintf("Mode changed from %s to %s", prev, m))
	return nil
}

// Mode returns the current mode.
func (e *Engine) Mode() Mode {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mode
}

// Expire removes rules whose TTL has passed and returns them.
func (e *Engine) Expire() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.opts.Now()
	var out []Rule
	for id, en := range e.rules {
		if en.rule.ExpiresAt == nil || now.Before(*en.rule.ExpiresAt) {
			continue
		}
		if err := e.removeAndSaveLocked(id, "ttl", "expire"); err == nil {
			out = append(out, en.rule)
		}
	}
	for _, f := range slices.Clone(e.filters) {
		if f.rule.ExpiresAt == nil || now.Before(*f.rule.ExpiresAt) {
			continue
		}
		if err := e.removeFilterLocked(f.rule.ID, "ttl", "expire"); err == nil {
			out = append(out, Rule{ID: f.rule.ID, Comment: f.rule.Comment, ExpiresAt: f.rule.ExpiresAt})
		}
	}
	return out
}

// Status returns the policy with current counters, rules sorted by
// creation time.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{
		Mode:           e.mode,
		KernelAttached: e.kernel != nil,
		MaxRules:       MaxRules,
		Rules:          make([]RuleStatus, 0, len(e.rules)),
		Audit:          slices.Clone(e.audit),
	}
	for _, en := range e.rules {
		rs := RuleStatus{Rule: en.rule}
		if e.kernel != nil {
			rs.Counters, _ = e.kernel.ReadCounter(en.slot)
		}
		st.Rules = append(st.Rules, rs)
	}
	sort.Slice(st.Rules, func(i, j int) bool {
		if !st.Rules[i].CreatedAt.Equal(st.Rules[j].CreatedAt) {
			return st.Rules[i].CreatedAt.Before(st.Rules[j].CreatedAt)
		}
		return st.Rules[i].ID < st.Rules[j].ID
	})
	st.MaxFilters = MaxFilterRules
	st.Filters = make([]FilterStatus, 0, len(e.filters))
	for i, f := range e.filters {
		fs := FilterStatus{FilterRule: f.rule, Position: i, Summary: f.rule.Match.Summary()}
		if e.kernel != nil {
			fs.Counters, _ = e.kernel.ReadFilterCounter(f.slot)
		}
		st.Filters = append(st.Filters, fs)
	}
	return st
}

// PollHits reports rules whose packet counter grew since the last report,
// at most once per HitRealert per rule. Growth in between is accumulated
// into the next report.
func (e *Engine) PollHits() []Hit {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.kernel == nil {
		return nil
	}
	now := e.opts.Now()
	var hits []Hit
	for id, en := range e.rules {
		c, err := e.kernel.ReadCounter(en.slot)
		if err != nil {
			continue
		}
		last := e.lastPackets[id]
		if c.Packets <= last {
			continue
		}
		if t, ok := e.lastReport[id]; ok && now.Sub(t) < e.opts.HitRealert {
			continue
		}
		hits = append(hits, Hit{
			Rule:     en.rule,
			Delta:    Counter{Packets: c.Packets - last},
			Total:    c,
			Enforced: en.rule.Action == ActionDrop && e.mode == ModeEnforce,
		})
		e.lastPackets[id] = c.Packets
		e.lastReport[id] = now
	}
	for _, f := range e.filters {
		c, err := e.kernel.ReadFilterCounter(f.slot)
		if err != nil {
			continue
		}
		id := f.rule.ID
		last := e.lastPackets[id]
		if c.Packets <= last {
			continue
		}
		if t, ok := e.lastReport[id]; ok && now.Sub(t) < e.opts.HitRealert {
			continue
		}
		fr := f.rule
		hits = append(hits, Hit{
			Rule:     Rule{ID: id},
			Filter:   &fr,
			Delta:    Counter{Packets: c.Packets - last},
			Total:    c,
			Enforced: fr.Verdict == VerdictDrop && e.mode == ModeEnforce,
		})
		e.lastPackets[id] = c.Packets
		e.lastReport[id] = now
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Rule.ID < hits[j].Rule.ID })
	return hits
}

func (e *Engine) auditLocked(actor, action, id, detail string) {
	e.audit = append(e.audit, AuditEntry{At: e.opts.Now().UTC(), Actor: actor, Action: action, RuleID: id, Detail: detail})
	if len(e.audit) > maxAudit {
		e.audit = e.audit[len(e.audit)-maxAudit:]
	}
}

// saveLocked writes the state file atomically (temp file + rename, 0600).
func (e *Engine) saveLocked() error {
	if e.opts.StatePath == "" {
		return nil
	}
	st := stateFile{Version: 1, Mode: e.mode, Rules: make([]Rule, 0, len(e.rules))}
	for _, en := range e.rules {
		if en.rule.ParentID != "" {
			continue // derived MAC quarantines are rebuilt by SyncHostnames
		}
		st.Rules = append(st.Rules, en.rule)
	}
	sort.Slice(st.Rules, func(i, j int) bool { return st.Rules[i].ID < st.Rules[j].ID })
	for _, f := range e.filters {
		st.Filters = append(st.Filters, f.rule)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(e.opts.StatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".policy-*.json")
	if err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	if err := os.Rename(tmp.Name(), e.opts.StatePath); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	return nil
}

func describe(r Rule) string {
	what := r.CIDR + " (" + string(r.Direction) + ")"
	switch {
	case r.Hostname != "" && r.ParentID == "":
		what = string(r.HostMatch) + " " + r.Hostname
	case r.MAC != "":
		what = "mac " + r.MAC
		if r.ParentID != "" {
			what += " (from " + r.ParentID + ")"
		}
	}
	s := string(r.Action) + " " + what
	if r.ExpiresAt != nil {
		s += " until " + r.ExpiresAt.Format(time.RFC3339)
	}
	if r.Comment != "" {
		s += ": " + r.Comment
	}
	return s
}
