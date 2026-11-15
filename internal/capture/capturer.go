package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/models"
)

const (
	// maxPending bounds alert captures waiting for their after-window.
	maxPending = 16
	// maxRateKeys bounds the per-address rate-limit state.
	maxRateKeys = 4096
	bytesPerMB  = 1 << 20
)

// ErrDisabled is returned when capture is not running.
var ErrDisabled = errors.New("packet capture is disabled")

// Source delivers frames from one interface until ctx ends.
type Source interface {
	Name() string
	Run(ctx context.Context, sink Sink) error
}

// Sink receives frames from a source. Frames are delivered in batches (one
// kernel block at a time) so the ring is locked once per batch.
type Sink interface {
	// Frames calls fill, which calls add for each frame in the batch. data
	// is only valid during add.
	Frames(fill func(add func(ts int64, data []byte, origLen int)))
	// Drops reports frames the kernel dropped since the previous call.
	Drops(n uint64)
}

// ifaceSink binds a Sink to one interface index.
type ifaceSink struct {
	c     *Capturer
	iface int
}

func (s ifaceSink) Frames(fill func(add func(int64, []byte, int))) {
	r := s.c.ring
	r.mu.Lock()
	defer r.mu.Unlock()
	fill(func(ts int64, data []byte, origLen int) { r.appendFrame(ts, s.iface, data, origLen) })
}

func (s ifaceSink) Drops(n uint64) { s.c.recordDrops(s.c.now(), n) }

// dropSample is one report of kernel drops, kept so a capture can say
// whether its window lost frames.
type dropSample struct {
	at time.Time
	n  uint64
}

// maxDropSamples keeps an hour of once-a-second reports.
const maxDropSamples = 3600

// Status summarises the capturer for the API and metrics.
type Status struct {
	Enabled       bool       `json:"enabled"`
	Interfaces    []string   `json:"interfaces"`
	BufferPackets int        `json:"buffer_packets"`
	BufferBytes   int        `json:"buffer_bytes"`
	BufferOldest  *time.Time `json:"buffer_oldest,omitempty"` // nil when empty
	Pending       int        `json:"pending"`
	Skipped       uint64     `json:"skipped"` // alert captures dropped (rate limit or queue full)
	// KernelDrops counts frames the kernel dropped because the reader fell
	// behind; captures covering those moments are incomplete.
	KernelDrops uint64 `json:"kernel_drops"`
}

// Capturer reads frames into a ring and writes captures from it.
type Capturer struct {
	cfg    alerts.CaptureConfig
	ring   *ring
	store  *store
	ifaces []Interface
	srcs   []Source
	now    func() time.Time

	mu       sync.Mutex
	drops    []dropSample
	dropsAll uint64
	lastByIP map[string]time.Time
	pending  int
	skipped  uint64
	timers   map[*time.Timer]struct{}
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
}

// New prepares a capturer. dataDir is used when cfg.Dir is empty.
func New(cfg alerts.CaptureConfig, dataDir string, srcs []Source) (*Capturer, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	dir := cfg.Dir
	if dir == "" {
		dir = filepath.Join(dataDir, "captures")
	}
	st, err := openStore(filepath.Clean(dir), cfg.MaxFiles, int64(cfg.MaxTotalMB)*bytesPerMB)
	if err != nil {
		return nil, err
	}
	c := &Capturer{
		cfg:      cfg,
		ring:     newRing(cfg.BufferMB*bytesPerMB, time.Duration(cfg.BufferSeconds)*time.Second),
		store:    st,
		srcs:     srcs,
		now:      time.Now,
		lastByIP: map[string]time.Time{},
		timers:   map[*time.Timer]struct{}{},
	}
	for _, s := range srcs {
		c.ifaces = append(c.ifaces, Interface{Name: s.Name(), Snaplen: cfg.Snaplen})
	}
	return c, nil
}

// Start runs one reader per source until Stop.
func (c *Capturer) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	for i, s := range c.srcs {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			err := s.Run(ctx, ifaceSink{c: c, iface: i})
			if err != nil && ctx.Err() == nil {
				log.Printf("capture: %s stopped: %v", s.Name(), err)
			}
		}()
	}
}

// Stop ends the readers and drops captures still waiting for their
// after-window.
func (c *Capturer) Stop() {
	c.mu.Lock()
	c.closed = true
	for t := range c.timers {
		t.Stop()
	}
	clear(c.timers)
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	_ = c.store.close()
}

// TriggerForAlert schedules a capture of the alerting device's traffic and
// returns its id, or "" when the alert does not qualify. It never blocks:
// it runs on the packet path with the monitor lock held.
func (c *Capturer) TriggerForAlert(a models.AlertEvent) string {
	o := c.cfg.OnAlert
	addr, err := netip.ParseAddr(a.DeviceIP)
	if !o.Enabled || err != nil || severityRank(a.Severity) < severityRank(o.MinSeverity) {
		return ""
	}
	now := c.now()
	key := addr.Unmap().String()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ""
	}
	if last, ok := c.lastByIP[key]; ok && now.Sub(last) < time.Duration(o.MinIntervalSeconds)*time.Second {
		c.skipped++
		return ""
	}
	if c.pending >= maxPending {
		c.skipped++
		return ""
	}
	if len(c.lastByIP) >= maxRateKeys {
		clear(c.lastByIP)
	}
	c.lastByIP[key] = now
	c.pending++

	meta := Capture{ID: newCaptureID(), CreatedAt: now, Reason: "alert", Rule: a.Rule, AlertID: a.ID, Address: key,
		From: now.Add(-time.Duration(o.BeforeSeconds) * time.Second)}
	var t *time.Timer
	t = time.AfterFunc(time.Duration(o.AfterSeconds)*time.Second, func() {
		c.mu.Lock()
		delete(c.timers, t)
		c.mu.Unlock()
		meta.To = c.now()
		if _, err := c.write(meta, addr); err != nil {
			log.Printf("capture: alert %s: %v", a.ID, err)
		}
		c.mu.Lock()
		c.pending--
		c.mu.Unlock()
	})
	c.timers[t] = struct{}{}
	return meta.ID
}

// CaptureNow writes the last `window` of traffic, for addr only when it is
// valid, and returns the stored capture.
func (c *Capturer) CaptureNow(addr netip.Addr, window time.Duration) (Capture, error) {
	if window <= 0 || window > time.Duration(c.cfg.BufferSeconds)*time.Second {
		return Capture{}, fmt.Errorf("window must be between 1s and the buffer length (%ds)", c.cfg.BufferSeconds)
	}
	now := c.now()
	meta := Capture{ID: newCaptureID(), CreatedAt: now, Reason: "manual", From: now.Add(-window), To: now}
	if addr.IsValid() {
		meta.Address = addr.Unmap().String()
	}
	return c.write(meta, addr)
}

func (c *Capturer) write(meta Capture, addr netip.Addr) (Capture, error) {
	var match func(Packet) bool
	if addr.IsValid() {
		match = func(p Packet) bool { return hasAddr(p.Data, addr) }
	}
	pkts := c.ring.selectPackets(meta.From, meta.To, match)
	meta.Drops = c.dropsBetween(meta.From, meta.To)
	return c.store.save(meta, c.ifaces, pkts)
}

func (c *Capturer) recordDrops(at time.Time, n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropsAll += n
	if len(c.drops) == maxDropSamples {
		c.drops = append(c.drops[:0], c.drops[1:]...)
	}
	c.drops = append(c.drops, dropSample{at: at, n: n})
}

// dropsBetween sums the drops reported for [from, to]. Each report covers
// the second before it, so the window extends one second past to.
func (c *Capturer) dropsBetween(from, to time.Time) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n uint64
	for _, d := range c.drops {
		if !d.at.Before(from) && !d.at.After(to.Add(time.Second)) {
			n += d.n
		}
	}
	return n
}

// List returns stored captures, newest first.
func (c *Capturer) List() []Capture { return c.store.list() }

// Open returns a stored capture file for download. The caller closes it.
func (c *Capturer) Open(id string) (io.ReadCloser, Capture, error) {
	f, meta, err := c.store.open(id)
	if err != nil {
		return nil, Capture{}, err
	}
	return f, meta, nil
}

// Delete removes a stored capture.
func (c *Capturer) Delete(id string) error { return c.store.remove(id) }

// Status reports buffer usage and queue state.
func (c *Capturer) Status() Status {
	packets, bytes, oldest := c.ring.stats()
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.ifaces))
	for _, i := range c.ifaces {
		names = append(names, i.Name)
	}
	s := Status{Enabled: true, Interfaces: names, BufferPackets: packets, BufferBytes: bytes,
		Pending: c.pending, Skipped: c.skipped, KernelDrops: c.dropsAll}
	if packets > 0 {
		s.BufferOldest = &oldest
	}
	return s
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
