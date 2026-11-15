package tui

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxBody bounds one API response; the device list of a large site is a
// few MB.
const maxBody = 32 << 20

// requestTimeout bounds one API call so a hung sensor never freezes the
// screen.
const requestTimeout = 5 * time.Second

// Client reads the Cerberus REST API.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// APIError is a non-2xx answer, with the server's error text when it sent
// one.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("%d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// NewClient builds a client for addr ("host:port" or a URL). caFile, when
// set, is the only CA trusted for https.
func NewClient(addr, token, caFile string) (*Client, error) {
	u, err := baseURL(addr)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if caFile != "" {
		pem, err := readFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file holds no PEM certificates")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &Client{base: u, token: token, http: &http.Client{Timeout: requestTimeout, Transport: tr}}, nil
}

// baseURL accepts a URL or a listen address. A wildcard listen address
// (0.0.0.0:8080, [::]:8080, :8080) means the local machine.
func baseURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if !strings.Contains(addr, "://") {
		host, port, err := net.SplitHostPort(addr)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("address %q: want host:port or a URL", addr)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		addr = "http://" + net.JoinHostPort(host, port)
	}
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("address %q: want http:// or https:// and a host", addr)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("address %q: bad port", addr)
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// Addr is the sensor address shown in the header.
func (c *Client) Addr() string { return c.base.Host }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &APIError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

// readFile reads an operator-supplied file through a root on its directory.
func readFile(path string) ([]byte, error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Base(path))
}
