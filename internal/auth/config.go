// Package auth decides who is calling the API and what they may do:
// bearer tokens (the admin CERBERUS_API_TOKEN and named tokens with a
// role) and OIDC sign-in for the Control Room with server-side sessions.
package auth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Role is what a caller may do. Higher roles include the lower ones.
type Role int

const (
	RoleNone    Role = iota // not signed in
	RoleViewer              // read everything
	RoleAnalyst             // also acknowledge alerts, approve flows, label assets
	RoleAdmin               // also change policy, zones, captures and settings
)

var roleNames = map[Role]string{RoleNone: "none", RoleViewer: "viewer", RoleAnalyst: "analyst", RoleAdmin: "admin"}

func (r Role) String() string { return roleNames[r] }

// ParseRole accepts viewer, analyst or admin.
func ParseRole(s string) (Role, bool) {
	for r, n := range roleNames {
		if r != RoleNone && n == strings.ToLower(strings.TrimSpace(s)) {
			return r, true
		}
	}
	return RoleNone, false
}

// Config is the optional CERBERUS_AUTH_CONFIG file. Without it, only the
// CERBERUS_API_TOKEN admin token exists and reads stay open.
type Config struct {
	// ProtectReads requires a signed-in user or a token for every API read
	// and /metrics, not only for changes.
	ProtectReads bool          `yaml:"protect_reads"`
	Tokens       []TokenConfig `yaml:"tokens"`
	OIDC         *OIDCConfig   `yaml:"oidc"`
}

// TokenConfig is a named API token. Only its SHA-256 is stored:
// printf %s "$TOKEN" | sha256sum
type TokenConfig struct {
	Name   string `yaml:"name"`
	Role   string `yaml:"role"`
	SHA256 string `yaml:"sha256"`
}

// OIDCConfig enables sign-in with an OpenID Connect provider.
type OIDCConfig struct {
	Issuer      string   `yaml:"issuer"`
	ClientID    string   `yaml:"client_id"`
	RedirectURL string   `yaml:"redirect_url"` // https://<cerberus>/auth/callback
	Scopes      []string `yaml:"scopes"`
	// ClientSecretFile holds the client secret; CERBERUS_OIDC_CLIENT_SECRET
	// overrides it. Secrets are never read from this YAML file.
	ClientSecretFile string `yaml:"client_secret_file"`
	// GroupsClaim names the ID token claim listing the user's groups.
	GroupsClaim string `yaml:"groups_claim"`
	// Roles maps role names to the groups that grant them; the highest
	// matching role wins.
	Roles map[string][]string `yaml:"roles"`
	// DefaultRole applies to users in none of the groups; empty refuses
	// them.
	DefaultRole  string `yaml:"default_role"`
	SessionHours int    `yaml:"session_hours"`

	clientSecret string
	roleGroups   map[string]Role
	defaultRole  Role
}

const (
	defaultSessionHours = 8
	maxSessionHours     = 24 * 7
	maxTokens           = 256
)

// LoadConfig reads and validates the auth file.
func LoadConfig(path string) (Config, error) {
	data, err := readFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read auth config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelt key must not silently disable something
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse auth config: %w", err)
	}
	return c, c.prepare()
}

// prepare validates the config and resolves secrets and role tables.
func (c *Config) prepare() error {
	if len(c.Tokens) > maxTokens {
		return fmt.Errorf("auth: at most %d tokens", maxTokens)
	}
	names := map[string]bool{}
	for i, t := range c.Tokens {
		if strings.TrimSpace(t.Name) == "" || names[t.Name] {
			return fmt.Errorf("auth.tokens[%d]: name must be set and unique", i)
		}
		names[t.Name] = true
		if _, ok := ParseRole(t.Role); !ok {
			return fmt.Errorf("auth.tokens[%d] %q: role must be viewer, analyst or admin", i, t.Name)
		}
		if b, err := hex.DecodeString(t.SHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("auth.tokens[%d] %q: sha256 must be 64 hex characters (printf %%s \"$TOKEN\" | sha256sum)", i, t.Name)
		}
	}
	if c.OIDC != nil {
		if err := c.OIDC.prepare(); err != nil {
			return err
		}
	}
	return nil
}

func (o *OIDCConfig) prepare() error {
	if u, err := url.Parse(o.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("auth.oidc.issuer must be an https URL")
	}
	if strings.TrimSpace(o.ClientID) == "" {
		return fmt.Errorf("auth.oidc.client_id is required")
	}
	u, err := url.Parse(o.RedirectURL)
	if err != nil || u.Host == "" || u.Path != "/auth/callback" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return fmt.Errorf("auth.oidc.redirect_url must be https://<host>/auth/callback (http only for localhost)")
	}
	o.clientSecret = os.Getenv("CERBERUS_OIDC_CLIENT_SECRET")
	if o.clientSecret == "" && o.ClientSecretFile != "" {
		b, err := readFile(o.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("auth.oidc.client_secret_file: %w", err)
		}
		o.clientSecret = strings.TrimSpace(string(b))
	}
	if o.clientSecret == "" {
		return fmt.Errorf("auth.oidc: set client_secret_file or CERBERUS_OIDC_CLIENT_SECRET")
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "profile", "email"}
	}
	if o.GroupsClaim == "" {
		o.GroupsClaim = "groups"
	}
	if o.SessionHours == 0 {
		o.SessionHours = defaultSessionHours
	}
	if o.SessionHours < 1 || o.SessionHours > maxSessionHours {
		return fmt.Errorf("auth.oidc.session_hours must be between 1 and %d", maxSessionHours)
	}
	o.roleGroups = map[string]Role{}
	for name, groups := range o.Roles {
		r, ok := ParseRole(name)
		if !ok {
			return fmt.Errorf("auth.oidc.roles: unknown role %q (want viewer, analyst or admin)", name)
		}
		for _, g := range groups {
			if r > o.roleGroups[g] {
				o.roleGroups[g] = r
			}
		}
	}
	if o.DefaultRole != "" {
		r, ok := ParseRole(o.DefaultRole)
		if !ok {
			return fmt.Errorf("auth.oidc.default_role must be viewer, analyst, admin or empty")
		}
		o.defaultRole = r
	}
	if len(o.roleGroups) == 0 && o.defaultRole == RoleNone {
		return fmt.Errorf("auth.oidc: map at least one group in roles, or set default_role")
	}
	return nil
}

// isLoopback reports whether a plain-http redirect is acceptable: browsers
// treat these hosts as secure, so the Secure session cookie still works.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (o *OIDCConfig) sessionTTL() time.Duration { return time.Duration(o.SessionHours) * time.Hour }

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
