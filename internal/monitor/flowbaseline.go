package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/tidwall/buntdb"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/industrial"
	"github.com/zrougamed/cerberus/internal/models"
)

// Flow statuses.
const (
	FlowLearned  = "learned"  // seen during the learning period
	FlowApproved = "approved" // first seen afterwards, accepted by an operator
	FlowNew      = "new"      // first seen afterwards, not reviewed yet
)

// Baseline states.
const (
	BaselineLearning  = "learning"
	BaselineEnforcing = "enforcing"
	BaselineDisabled  = "disabled"
)

const (
	flowKeyPrefix   = "flow:"
	flowMetaKey     = "flowbaseline:meta"
	maxFlowsListed  = 5000
	defaultFlowList = 500
)

// FlowEntry is one (client, server, protocol, operation class) tuple.
type FlowEntry struct {
	ID        string    `json:"id"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	Protocol  string    `json:"protocol"`
	Class     string    `json:"class"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     uint64    `json:"count"`
}

// BaselineStatus summarises the flow baseline.
type BaselineStatus struct {
	State         string    `json:"state"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	LearningUntil time.Time `json:"learning_until,omitempty"`
	Learned       int       `json:"learned"`
	Approved      int       `json:"approved"`
	New           int       `json:"new"`
	Dropped       uint64    `json:"dropped"`
	MaxFlows      int       `json:"max_flows"`
}

type baselineMeta struct {
	StartedAt     time.Time `json:"started_at"`
	LearningUntil time.Time `json:"learning_until"`
}

// flowBaseline is guarded by NetworkMonitor.mu.
type flowBaseline struct {
	cfg       alerts.FlowBaselineConfig
	meta      baselineMeta
	flows     map[string]*FlowEntry
	dirty     map[string]struct{} // ids to write
	deleted   map[string]struct{} // ids to remove from storage
	metaDirty bool
	dropped   uint64
}

func flowID(client, server, protocol, class string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(client + "|" + server + "|" + protocol + "|" + class))
	return fmt.Sprintf("%016x", h.Sum64())
}

// newFlowBaseline loads a stored baseline, or starts learning at now.
func newFlowBaseline(cfg alerts.FlowBaselineConfig, db *buntdb.DB, now time.Time) *flowBaseline {
	if !cfg.Enabled {
		return nil
	}
	b := &flowBaseline{cfg: cfg, flows: map[string]*FlowEntry{}, dirty: map[string]struct{}{}, deleted: map[string]struct{}{}}
	err := db.View(func(tx *buntdb.Tx) error {
		if v, err := tx.Get(flowMetaKey); err == nil {
			if err := json.Unmarshal([]byte(v), &b.meta); err != nil {
				log.Printf("monitor: ignoring corrupt flow baseline header: %v", err)
			}
		}
		return tx.AscendKeys(flowKeyPrefix+"*", func(_, v string) bool {
			var e FlowEntry
			if err := json.Unmarshal([]byte(v), &e); err == nil && e.ID != "" {
				b.flows[e.ID] = &e
			}
			return true
		})
	})
	if err != nil {
		log.Printf("monitor: loading flow baseline: %v", err)
	}
	if b.meta.StartedAt.IsZero() {
		b.restart(now)
	}
	return b
}

func (b *flowBaseline) restart(now time.Time) {
	for id := range b.flows {
		b.deleted[id] = struct{}{}
	}
	clear(b.flows)
	clear(b.dirty)
	b.dropped = 0
	b.meta = baselineMeta{StartedAt: now, LearningUntil: now.Add(time.Duration(b.cfg.LearningHours) * time.Hour)}
	b.metaDirty = true
}

func (b *flowBaseline) learning(now time.Time) bool { return now.Before(b.meta.LearningUntil) }

// observeFlow records an industrial request in the baseline and raises
// baseline_new_flow for a tuple first seen after learning. Caller holds
// nm.mu.
func (nm *NetworkMonitor) observeFlow(device *models.DeviceInfo, msg industrial.Message, client, server string, now time.Time) {
	b := nm.flowBaseline
	if b == nil || msg.Response {
		return
	}
	class := string(msg.Class)
	id := flowID(client, server, msg.Protocol, class)
	if e, ok := b.flows[id]; ok {
		e.LastSeen = now
		e.Count++
		b.dirty[id] = struct{}{}
		return
	}
	if len(b.flows) >= b.cfg.MaxFlows {
		b.dropped++
		return
	}
	e := &FlowEntry{ID: id, Client: client, Server: server, Protocol: msg.Protocol, Class: class,
		Status: FlowLearned, FirstSeen: now, LastSeen: now, Count: 1}
	b.flows[id] = e
	b.dirty[id] = struct{}{}
	delete(b.deleted, id)
	if b.learning(now) {
		return
	}
	e.Status = FlowNew
	nm.appendAlert(models.AlertEvent{
		ID:         fmt.Sprintf("%d-%s-%s", now.UnixNano(), device.MAC, alerts.RuleBaselineNewFlow),
		DeviceMAC:  device.MAC,
		DeviceIP:   device.IP,
		Vendor:     device.Vendor,
		Rule:       alerts.RuleBaselineNewFlow,
		Severity:   b.cfg.Severity,
		Message:    fmt.Sprintf("New industrial flow %s -> %s: %s %s (not seen while learning)", client, server, protocolLabels[msg.Protocol], class),
		ObservedAt: now,
	})
}

// flushBaseline writes changed baseline records to storage.
func (nm *NetworkMonitor) flushBaseline() {
	nm.mu.Lock()
	b := nm.flowBaseline
	if b == nil || (len(b.dirty) == 0 && len(b.deleted) == 0 && !b.metaDirty) {
		nm.mu.Unlock()
		return
	}
	writes := make(map[string]string, len(b.dirty))
	for id := range b.dirty {
		if e, ok := b.flows[id]; ok {
			data, _ := json.Marshal(e) // plain struct, cannot fail
			writes[flowKeyPrefix+id] = string(data)
		}
	}
	deletes := make([]string, 0, len(b.deleted))
	for id := range b.deleted {
		deletes = append(deletes, flowKeyPrefix+id)
	}
	var meta string
	if b.metaDirty {
		data, _ := json.Marshal(b.meta)
		meta = string(data)
	}
	clear(b.dirty)
	clear(b.deleted)
	b.metaDirty = false
	nm.mu.Unlock()

	err := nm.db.Update(func(tx *buntdb.Tx) error {
		for _, k := range deletes {
			if _, err := tx.Delete(k); err != nil && !errors.Is(err, buntdb.ErrNotFound) {
				return err
			}
		}
		for k, v := range writes {
			if _, _, err := tx.Set(k, v, nil); err != nil {
				return err
			}
		}
		if meta != "" {
			if _, _, err := tx.Set(flowMetaKey, meta, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("monitor: persisting flow baseline failed: %v", err)
	}
}

// GetBaselineStatus reports the baseline state and counts.
func (nm *NetworkMonitor) GetBaselineStatus() BaselineStatus {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	b := nm.flowBaseline
	if b == nil {
		return BaselineStatus{State: BaselineDisabled}
	}
	s := BaselineStatus{State: BaselineEnforcing, StartedAt: b.meta.StartedAt, LearningUntil: b.meta.LearningUntil,
		Dropped: b.dropped, MaxFlows: b.cfg.MaxFlows}
	if b.learning(time.Now()) {
		s.State = BaselineLearning
	}
	for _, e := range b.flows {
		switch e.Status {
		case FlowLearned:
			s.Learned++
		case FlowApproved:
			s.Approved++
		case FlowNew:
			s.New++
		}
	}
	return s
}

// GetBaselineFlows lists flows, optionally of one status. New flows come
// newest first; the rest are ordered by client, server and protocol.
func (nm *NetworkMonitor) GetBaselineFlows(status string, limit int) []FlowEntry {
	if limit <= 0 {
		limit = defaultFlowList
	}
	limit = min(limit, maxFlowsListed)
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	out := []FlowEntry{}
	if nm.flowBaseline == nil {
		return out
	}
	for _, e := range nm.flowBaseline.flows {
		if status == "" || e.Status == status {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Status == FlowNew) != (b.Status == FlowNew) {
			return a.Status == FlowNew
		}
		if a.Status == FlowNew {
			return a.FirstSeen.After(b.FirstSeen)
		}
		return strings.Join([]string{a.Client, a.Server, a.Protocol, a.Class}, "|") <
			strings.Join([]string{b.Client, b.Server, b.Protocol, b.Class}, "|")
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ApproveFlows marks new flows as approved and returns how many changed.
func (nm *NetworkMonitor) ApproveFlows(ids []string) int {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if nm.flowBaseline == nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		if e, ok := nm.flowBaseline.flows[id]; ok && e.Status == FlowNew {
			e.Status = FlowApproved
			nm.flowBaseline.dirty[id] = struct{}{}
			n++
		}
	}
	return n
}

// ForgetFlows removes flows from the baseline; the next matching request
// is treated as never seen. Returns how many were removed.
func (nm *NetworkMonitor) ForgetFlows(ids []string) int {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if nm.flowBaseline == nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		if _, ok := nm.flowBaseline.flows[id]; ok {
			delete(nm.flowBaseline.flows, id)
			delete(nm.flowBaseline.dirty, id)
			nm.flowBaseline.deleted[id] = struct{}{}
			n++
		}
	}
	return n
}

// RelearnBaseline drops every flow and starts a new learning period.
// It reports false when the baseline is disabled.
func (nm *NetworkMonitor) RelearnBaseline() bool {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if nm.flowBaseline == nil {
		return false
	}
	nm.flowBaseline.restart(time.Now())
	return true
}
