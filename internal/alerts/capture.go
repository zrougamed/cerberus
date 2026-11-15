package alerts

import "fmt"

// CaptureConfig controls packet capture around alerts. Off by default: it
// reads every frame on the capture interfaces into memory.
type CaptureConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Interfaces to read; empty means the interfaces Cerberus attached to.
	Interfaces []string `yaml:"interfaces" json:"interfaces"`
	// Snaplen caps bytes kept per frame. 1518 holds a full Ethernet frame.
	Snaplen int `yaml:"snaplen" json:"snaplen"`
	// BufferSeconds and BufferMB bound the in-memory ring; whichever is
	// hit first evicts the oldest frames.
	BufferSeconds int            `yaml:"buffer_seconds" json:"buffer_seconds"`
	BufferMB      int            `yaml:"buffer_mb" json:"buffer_mb"`
	OnAlert       CaptureOnAlert `yaml:"on_alert" json:"on_alert"`
	// MaxFiles and MaxTotalMB bound stored captures; the oldest go first.
	MaxFiles   int `yaml:"max_files" json:"max_files"`
	MaxTotalMB int `yaml:"max_total_mb" json:"max_total_mb"`
	// Dir defaults to <data dir>/captures.
	Dir string `yaml:"dir" json:"dir"`
}

// CaptureOnAlert writes a capture when a rule alert fires.
type CaptureOnAlert struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	MinSeverity string `yaml:"min_severity" json:"min_severity"`
	// BeforeSeconds of history and AfterSeconds of follow-up traffic are
	// saved for the alerting device's address.
	BeforeSeconds int `yaml:"before_seconds" json:"before_seconds"`
	AfterSeconds  int `yaml:"after_seconds" json:"after_seconds"`
	// MinIntervalSeconds limits captures per device address.
	MinIntervalSeconds int `yaml:"min_interval_seconds" json:"min_interval_seconds"`
}

type captureOverlay struct {
	Enabled       *bool    `yaml:"enabled" json:"enabled"`
	Interfaces    []string `yaml:"interfaces" json:"interfaces"`
	Snaplen       *int     `yaml:"snaplen" json:"snaplen"`
	BufferSeconds *int     `yaml:"buffer_seconds" json:"buffer_seconds"`
	BufferMB      *int     `yaml:"buffer_mb" json:"buffer_mb"`
	OnAlert       *struct {
		Enabled            *bool   `yaml:"enabled" json:"enabled"`
		MinSeverity        *string `yaml:"min_severity" json:"min_severity"`
		BeforeSeconds      *int    `yaml:"before_seconds" json:"before_seconds"`
		AfterSeconds       *int    `yaml:"after_seconds" json:"after_seconds"`
		MinIntervalSeconds *int    `yaml:"min_interval_seconds" json:"min_interval_seconds"`
	} `yaml:"on_alert" json:"on_alert"`
	MaxFiles   *int    `yaml:"max_files" json:"max_files"`
	MaxTotalMB *int    `yaml:"max_total_mb" json:"max_total_mb"`
	Dir        *string `yaml:"dir" json:"dir"`
}

func defaultCapture() CaptureConfig {
	return CaptureConfig{
		Snaplen:       1518,
		BufferSeconds: 120,
		BufferMB:      64,
		OnAlert: CaptureOnAlert{Enabled: true, MinSeverity: "high", BeforeSeconds: 30, AfterSeconds: 10,
			MinIntervalSeconds: 300},
		MaxFiles:   50,
		MaxTotalMB: 512,
	}
}

func setIf[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

func mergeCapture(dst *CaptureConfig, src *captureOverlay) {
	if src == nil {
		return
	}
	setIf(&dst.Enabled, src.Enabled)
	if src.Interfaces != nil {
		dst.Interfaces = append([]string(nil), src.Interfaces...)
	}
	setIf(&dst.Snaplen, src.Snaplen)
	setIf(&dst.BufferSeconds, src.BufferSeconds)
	setIf(&dst.BufferMB, src.BufferMB)
	setIf(&dst.MaxFiles, src.MaxFiles)
	setIf(&dst.MaxTotalMB, src.MaxTotalMB)
	setIf(&dst.Dir, src.Dir)
	if o := src.OnAlert; o != nil {
		setIf(&dst.OnAlert.Enabled, o.Enabled)
		setIf(&dst.OnAlert.MinSeverity, o.MinSeverity)
		setIf(&dst.OnAlert.BeforeSeconds, o.BeforeSeconds)
		setIf(&dst.OnAlert.AfterSeconds, o.AfterSeconds)
		setIf(&dst.OnAlert.MinIntervalSeconds, o.MinIntervalSeconds)
	}
}

// Limits keep a misconfigured capture from exhausting memory or disk.
const (
	minSnaplen        = 64
	maxSnaplen        = 65535
	maxBufferSeconds  = 3600
	maxBufferMB       = 1024
	maxAfterSeconds   = 300
	maxCaptureFiles   = 10000
	maxCaptureTotalMB = 100000
)

func validateCapture(c CaptureConfig) error {
	if !c.Enabled {
		return nil
	}
	switch {
	case c.Snaplen < minSnaplen || c.Snaplen > maxSnaplen:
		return fmt.Errorf("capture.snaplen must be between %d and %d", minSnaplen, maxSnaplen)
	case c.BufferSeconds < 1 || c.BufferSeconds > maxBufferSeconds:
		return fmt.Errorf("capture.buffer_seconds must be between 1 and %d", maxBufferSeconds)
	case c.BufferMB < 1 || c.BufferMB > maxBufferMB:
		return fmt.Errorf("capture.buffer_mb must be between 1 and %d", maxBufferMB)
	case c.MaxFiles < 1 || c.MaxFiles > maxCaptureFiles:
		return fmt.Errorf("capture.max_files must be between 1 and %d", maxCaptureFiles)
	case c.MaxTotalMB < 1 || c.MaxTotalMB > maxCaptureTotalMB:
		return fmt.Errorf("capture.max_total_mb must be between 1 and %d", maxCaptureTotalMB)
	}
	if o := c.OnAlert; o.Enabled {
		switch {
		case !validSeverity(o.MinSeverity):
			return fmt.Errorf("capture.on_alert: unknown min_severity %q (want low|medium|high)", o.MinSeverity)
		case o.BeforeSeconds < 0 || o.BeforeSeconds > c.BufferSeconds:
			return fmt.Errorf("capture.on_alert.before_seconds must be between 0 and buffer_seconds (%d)", c.BufferSeconds)
		case o.AfterSeconds < 0 || o.AfterSeconds > maxAfterSeconds:
			return fmt.Errorf("capture.on_alert.after_seconds must be between 0 and %d", maxAfterSeconds)
		case o.MinIntervalSeconds < 0:
			return fmt.Errorf("capture.on_alert.min_interval_seconds must be >= 0")
		}
	}
	return nil
}
