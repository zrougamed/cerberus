package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testPKI makes a CA and a server certificate for 127.0.0.1 / "collector".
func testPKI(t *testing.T) (caPEM []byte, server tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "collector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"collector"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

// collector accepts TLS connections and returns octet-counted frames.
func collector(t *testing.T, cert tls.Certificate, dropFirst bool) (addr string, frames <-chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan string, 16)
	go func() {
		first := true
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if first && dropFirst {
				first = false
				r := bufio.NewReader(conn)
				if f, err := readFrame(r); err == nil {
					out <- f
				}
				_ = conn.Close() // the next write on the client side fails
				continue
			}
			go func(c net.Conn) {
				r := bufio.NewReader(c)
				for {
					f, err := readFrame(r)
					if err != nil {
						return
					}
					out <- f
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), out
}

func readFrame(r *bufio.Reader) (string, error) {
	n, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(r, buf)
	return string(buf), err
}

func writeCA(t *testing.T, pemBytes []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTLSSyslog_DeliversRFC5425Frames(t *testing.T) {
	caPEM, cert := testPKI(t)
	addr, frames := collector(t, cert, false)
	d, err := New(Config{Enabled: true, MinSeverity: "low", Syslog: SyslogConfig{
		Network: "tls", Address: addr, Tag: "cerb", Format: SyslogFormatCEF, CAFile: writeCA(t, caPEM)}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Notify(sampleEvent)
	select {
	case f := <-frames:
		// <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG; daemon.alert = 3*8+1.
		parts := strings.SplitN(f, " ", 8)
		if len(parts) != 8 || parts[0] != "<25>1" || parts[3] != "cerb" || parts[5] != "-" || parts[6] != "-" {
			t.Fatalf("frame header = %q", f)
		}
		if _, err := time.Parse(time.RFC3339Nano, parts[1]); err != nil {
			t.Fatalf("timestamp %q: %v", parts[1], err)
		}
		if !strings.HasPrefix(parts[7], "CEF:0|Cerberus|Cerberus|") {
			t.Fatalf("message = %q", parts[7])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frame received")
	}
}

func TestTLSSyslog_ReconnectsAfterDrop(t *testing.T) {
	caPEM, cert := testPKI(t)
	addr, frames := collector(t, cert, true)
	s, err := newTLSSyslog(SyslogConfig{Address: addr, CAFile: writeCA(t, caPEM)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.send("medium", "first"); err != nil {
		t.Fatal(err)
	}
	if f := <-frames; !strings.HasPrefix(f, "<28>1 ") || !strings.HasSuffix(f, " first") {
		t.Fatalf("first frame = %q", f)
	}
	// The collector closed the connection: writes fail until a reconnect.
	deadline := time.Now().Add(5 * time.Second)
	var sent bool
	for !sent && time.Now().Before(deadline) {
		sent = s.send("low", "second") == nil && func() bool {
			select {
			case f := <-frames:
				return strings.HasPrefix(f, "<30>1 ") && strings.HasSuffix(f, " second")
			case <-time.After(300 * time.Millisecond):
				return false
			}
		}()
	}
	if !sent {
		t.Fatal("did not reconnect")
	}
}

func TestTLSSyslog_RejectsUntrustedCollector(t *testing.T) {
	_, cert := testPKI(t)
	otherCA, _ := testPKI(t)
	addr, _ := collector(t, cert, false)
	s, err := newTLSSyslog(SyslogConfig{Address: addr, CAFile: writeCA(t, otherCA)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.send("high", "x"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted collector accepted: %v", err)
	}
	// Server name override: the certificate names "collector", not "other".
	caPEM, cert2 := testPKI(t)
	addr2, _ := collector(t, cert2, false)
	s2, _ := newTLSSyslog(SyslogConfig{Address: addr2, CAFile: writeCA(t, caPEM), ServerName: "other"})
	if err := s2.send("high", "x"); err == nil {
		t.Fatal("wrong server name accepted")
	}
	s3, _ := newTLSSyslog(SyslogConfig{Address: addr2, CAFile: writeCA(t, caPEM), ServerName: "collector"})
	if err := s3.send("high", "x"); err != nil {
		t.Fatalf("server name override: %v", err)
	}
	_ = s3.Close()
	_ = s3.Close()
}

func TestSyslogValidation(t *testing.T) {
	t.Parallel()
	caPEM, _ := testPKI(t)
	ca := writeCA(t, caPEM)
	junk := writeCA(t, []byte("not a certificate"))
	tests := []struct {
		name string
		cfg  SyslogConfig
		want string
	}{
		{"unknown network", SyslogConfig{Address: "x:1", Network: "quic"}, "unknown"},
		{"unknown format", SyslogConfig{Address: "x:1", Format: "gelf"}, "format"},
		{"tls without port", SyslogConfig{Address: "collector", Network: "tls"}, "address"},
		{"missing ca file", SyslogConfig{Address: "c:6514", Network: "tls", CAFile: "/nope/ca.pem"}, "ca_file"},
		{"ca file without certs", SyslogConfig{Address: "c:6514", Network: "tls", CAFile: junk}, "no PEM"},
		{"ca file on udp", SyslogConfig{Address: "c:514", CAFile: ca}, "only applies"},
		{"valid tls", SyslogConfig{Address: "c:6514", Network: "tls", CAFile: ca, Format: "leef"}, ""},
	}
	for _, tt := range tests {
		err := Validate(Config{Enabled: true, Syslog: tt.cfg})
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
	if _, err := openSyslog(SyslogConfig{Address: "c", Network: "tls"}); err == nil {
		t.Error("bad tls address opened")
	}
}

func TestStdSyslog_SeveritiesAndDefaultTag(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s, err := openSyslog(SyslogConfig{Address: pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// daemon facility: alert 25, warning 28, info 30.
	for sev, pri := range map[string]string{"high": "<25>", "medium": "<28>", "low": "<30>"} {
		if err := s.send(sev, "probe-"+sev); err != nil {
			t.Fatal(err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		msg := string(buf[:n])
		if !strings.HasPrefix(msg, pri) || !strings.Contains(msg, "cerberus[") || !strings.HasSuffix(strings.TrimSpace(msg), "probe-"+sev) {
			t.Fatalf("%s: %q", sev, msg)
		}
	}
	if _, err := openSyslog(SyslogConfig{Address: "127.0.0.1:1", Network: "unixgram"}); err == nil {
		t.Error("bad unix socket opened")
	}
}
