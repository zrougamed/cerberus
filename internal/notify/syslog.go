package notify

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// syslogSink sends one formatted message at a severity.
type syslogSink interface {
	send(severity, msg string) error
	Close() error
}

// stdSyslog is the standard library writer, used for udp, tcp and unix.
type stdSyslog struct{ w *syslog.Writer }

func (s stdSyslog) send(severity, msg string) error {
	switch strings.ToLower(severity) {
	case "high":
		return s.w.Alert(msg)
	case "medium":
		return s.w.Warning(msg)
	default:
		return s.w.Info(msg)
	}
}

func (s stdSyslog) Close() error { return s.w.Close() }

// tlsDialTimeout and tlsWriteTimeout keep a dead collector from stalling
// the notification queue.
const (
	tlsDialTimeout  = 5 * time.Second
	tlsWriteTimeout = 5 * time.Second
	facilityDaemon  = 3
	rfc5424Version  = 1
	nilValue        = "-"
)

// tlsSyslog sends RFC 5424 messages over TLS with RFC 5425 octet-counting
// framing. It reconnects on the next message after a failure. It is used
// from the dispatcher goroutine only.
type tlsSyslog struct {
	addr     string
	tag      string
	hostname string
	cfg      *tls.Config
	conn     net.Conn
	now      func() time.Time
}

func newTLSSyslog(c SyslogConfig) (*tlsSyslog, error) {
	tc, err := tlsConfig(c)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = nilValue
	}
	tag := c.Tag
	if tag == "" {
		tag = "cerberus"
	}
	return &tlsSyslog{addr: c.Address, tag: tag, hostname: host, cfg: tc, now: time.Now}, nil
}

// tlsConfig builds the client config: system roots unless a CA file pins
// the collector's issuer, server name from the address unless set.
func tlsConfig(c SyslogConfig) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(c.Address)
	if err != nil {
		return nil, fmt.Errorf("syslog address %q: %w", c.Address, err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if c.ServerName != "" {
		tc.ServerName = c.ServerName
	}
	if c.CAFile != "" {
		pem, err := readFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("syslog ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("syslog ca_file %q holds no PEM certificates", c.CAFile)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

func (s *tlsSyslog) send(severity, msg string) error {
	if s.conn == nil {
		d := &net.Dialer{Timeout: tlsDialTimeout}
		conn, err := tls.DialWithDialer(d, "tcp", s.addr, s.cfg)
		if err != nil {
			return fmt.Errorf("connect to %s: %w", s.addr, err)
		}
		s.conn = conn
	}
	frame := s.frame(severity, msg)
	_ = s.conn.SetWriteDeadline(s.now().Add(tlsWriteTimeout))
	if _, err := s.conn.Write(frame); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("write to %s: %w", s.addr, err)
	}
	return nil
}

// frame builds "<len> <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG".
func (s *tlsSyslog) frame(severity, msg string) []byte {
	sev := 6 // informational
	switch strings.ToLower(severity) {
	case "high":
		sev = 1 // alert
	case "medium":
		sev = 4 // warning
	}
	line := fmt.Sprintf("<%d>%d %s %s %s %d %s %s %s",
		facilityDaemon*8+sev, rfc5424Version, s.now().UTC().Format(time.RFC3339Nano),
		s.hostname, s.tag, os.Getpid(), nilValue, nilValue, msg)
	return []byte(fmt.Sprintf("%d %s", len(line), line))
}

func (s *tlsSyslog) Close() error {
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// openSyslog connects the configured syslog sink.
func openSyslog(c SyslogConfig) (syslogSink, error) {
	network := strings.ToLower(c.Network)
	if network == "" {
		network = "udp"
	}
	if network == "tls" {
		return newTLSSyslog(c)
	}
	tag := c.Tag
	if tag == "" {
		tag = "cerberus"
	}
	w, err := syslog.Dial(network, c.Address, syslog.LOG_ALERT|syslog.LOG_DAEMON, tag)
	if err != nil {
		return nil, err
	}
	return stdSyslog{w: w}, nil
}

// readFile reads an operator-supplied file through a root on its
// directory, so the name cannot climb out of it.
func readFile(path string) ([]byte, error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Base(path))
}
