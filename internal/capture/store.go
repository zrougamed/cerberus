package capture

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"time"
)

// ErrNotFound is returned for an unknown or malformed capture id.
var ErrNotFound = errors.New("capture not found")

// Capture describes one stored pcapng file.
type Capture struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"` // "alert" or "manual"
	Rule      string    `json:"rule,omitempty"`
	AlertID   string    `json:"alert_id,omitempty"`
	Address   string    `json:"address,omitempty"` // empty: all traffic
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Packets   int       `json:"packets"`
	Bytes     int64     `json:"bytes"` // file size
}

var captureIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

func newCaptureID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// store keeps pcapng files and their metadata in one directory. All file
// access goes through an os.Root, so no name can reach outside it, and
// files are owner-only: captures hold full packet payloads.
type store struct {
	dir      string
	root     *os.Root
	maxFiles int
	maxBytes int64
}

func openStore(dir string, maxFiles int, maxBytes int64) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create capture dir: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open capture dir: %w", err)
	}
	return &store{dir: dir, root: root, maxFiles: maxFiles, maxBytes: maxBytes}, nil
}

func (s *store) close() error { return s.root.Close() }

func names(id string) (pcap, meta string) { return id + ".pcapng", id + ".json" }

// save writes the capture and its metadata, then applies retention.
func (s *store) save(c Capture, ifaces []Interface, pkts []Packet) (Capture, error) {
	if !captureIDPattern.MatchString(c.ID) {
		return Capture{}, fmt.Errorf("invalid capture id %q", c.ID)
	}
	pcapName, metaName := names(c.ID)
	f, err := s.root.OpenFile(pcapName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Capture{}, fmt.Errorf("create capture file: %w", err)
	}
	if err := writePcapng(f, ifaces, pkts); err != nil {
		_ = f.Close()
		_ = s.root.Remove(pcapName)
		return Capture{}, fmt.Errorf("write capture: %w", err)
	}
	info, statErr := f.Stat()
	if err := errors.Join(f.Close(), statErr); err != nil {
		_ = s.root.Remove(pcapName)
		return Capture{}, fmt.Errorf("close capture: %w", err)
	}
	c.Packets = len(pkts)
	c.Bytes = info.Size()
	data, _ := json.Marshal(c) // plain struct, cannot fail
	if err := s.root.WriteFile(metaName, data, 0o600); err != nil {
		_ = s.root.Remove(pcapName)
		return Capture{}, fmt.Errorf("write capture metadata: %w", err)
	}
	s.enforceRetention()
	return c, nil
}

// list returns stored captures, newest first. Files without readable
// metadata are skipped.
func (s *store) list() []Capture {
	metas, _ := fs.Glob(s.root.FS(), "*.json")
	out := make([]Capture, 0, len(metas))
	for _, m := range metas {
		data, err := s.root.ReadFile(m)
		if err != nil {
			continue
		}
		var c Capture
		if json.Unmarshal(data, &c) != nil || !captureIDPattern.MatchString(c.ID) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// open returns the pcapng file for id. The caller closes it.
func (s *store) open(id string) (*os.File, Capture, error) {
	if !captureIDPattern.MatchString(id) {
		return nil, Capture{}, ErrNotFound
	}
	for _, c := range s.list() {
		if c.ID == id {
			pcapName, _ := names(id)
			f, err := s.root.Open(pcapName)
			if err != nil {
				return nil, Capture{}, ErrNotFound
			}
			return f, c, nil
		}
	}
	return nil, Capture{}, ErrNotFound
}

func (s *store) remove(id string) error {
	if !captureIDPattern.MatchString(id) {
		return ErrNotFound
	}
	pcapName, metaName := names(id)
	if _, err := s.root.Stat(metaName); err != nil {
		return ErrNotFound
	}
	return errors.Join(s.root.Remove(pcapName), s.root.Remove(metaName))
}

// enforceRetention removes the oldest captures until both limits hold.
func (s *store) enforceRetention() {
	all := s.list()
	var total int64
	for _, c := range all {
		total += c.Bytes
	}
	for i := len(all) - 1; i >= 0 && (len(all) > s.maxFiles || total > s.maxBytes); i-- {
		if s.remove(all[i].ID) == nil {
			total -= all[i].Bytes
			all = all[:i]
		}
	}
}
