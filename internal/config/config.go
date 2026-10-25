// Package config loads and validates the gateway's JSON configuration file:
// identity providers, apps and their access policies. Secrets are never
// written in the file; it names environment variables or files that hold
// them.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Limits and defaults.
const (
	MaxFileBytes      = 1 << 20
	maxProviders      = 64
	maxApps           = 1024
	maxListEntries    = 10_000
	DefaultSkew       = 2 * time.Minute
	MaxSkew           = 10 * time.Minute
	DefaultTokenTTL   = 2 * time.Minute
	MaxTokenTTL       = 15 * time.Minute
	DefaultIdle       = 8 * time.Hour
	DefaultAbsolute   = 24 * time.Hour
	MaxAbsolute       = 30 * 24 * time.Hour
	ProviderOIDC      = "oidc"
	ProviderSAML      = "saml"
	maxDisplayNameLen = 64
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Duration is a time.Duration written as a Go duration string ("8h").
type Duration time.Duration

// UnmarshalJSON parses "90s", "8h" and so on.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings like "90s" or "8h"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(v)
	return nil
}

// Config is the whole file.
type Config struct {
	PublicURL        string     `json:"public_url"`
	CookieDomain     string     `json:"cookie_domain"`
	Session          Session    `json:"session"`
	ClockSkew        Duration   `json:"clock_skew"`
	RedirectHosts    []string   `json:"redirect_hosts"`
	UpstreamTokenTTL Duration   `json:"upstream_token_ttl"`
	Providers        []Provider `json:"providers"`
	Apps             []App      `json:"apps"`

	// Filled in by Load.
	Public *url.URL `json:"-"`
}

// Session timeouts.
type Session struct {
	IdleTimeout     Duration `json:"idle_timeout"`
	AbsoluteTimeout Duration `json:"absolute_timeout"`
}

// Provider is one identity provider.
type Provider struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`

	// OpenID Connect.
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	ClientSecretEnv       string   `json:"client_secret_env"`
	ClientSecretFile      string   `json:"client_secret_file"`
	ClientAuth            string   `json:"client_auth"`
	Scopes                []string `json:"scopes"`
	Algorithms            []string `json:"algorithms"`
	EmailClaim            string   `json:"email_claim"`
	NameClaim             string   `json:"name_claim"`
	GroupsClaim           string   `json:"groups_claim"`
	Userinfo              bool     `json:"userinfo"`
	TrustedAudiences      []string `json:"trusted_audiences"`
	CAFile                string   `json:"ca_file"`
	PostLogoutRedirectURL string   `json:"post_logout_redirect_url"`

	// SAML 2.0.
	IdPMetadataFile string `json:"idp_metadata_file"`
	IdPMetadataURL  string `json:"idp_metadata_url"`
	EntityID        string `json:"entity_id"`
	SPKeyFile       string `json:"sp_key_file"`
	SPCertFile      string `json:"sp_cert_file"`
	SignRequests    bool   `json:"sign_requests"`
	NameIDFormat    string `json:"name_id_format"`
	EmailAttribute  string `json:"email_attribute"`
	NameAttribute   string `json:"name_attribute"`
	GroupsAttribute string `json:"groups_attribute"`

	// Filled in by Load.
	ClientSecret string `json:"-"`
}

// App is one protected application.
type App struct {
	ID         string   `json:"id"`
	Hosts      []string `json:"hosts"`
	Providers  []string `json:"providers"`
	Allow      Allow    `json:"allow"`
	DefaultURL string   `json:"default_url"`
}

// Allow is an app's access rule. Nothing is allowed by default.
type Allow struct {
	AnyUser      bool     `json:"any_user"`
	Emails       []string `json:"emails"`
	EmailDomains []string `json:"email_domains"`
	Groups       []string `json:"groups"`
}

// Load reads and validates the file at path. getenv resolves
// client_secret_env.
func Load(path string, getenv func(string) string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("config: file larger than %d bytes", MaxFileBytes)
	}
	return Parse(b, getenv)
}

// Parse validates a configuration document.
func Parse(b []byte, getenv func(string) string) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}
	if dec.More() {
		return nil, errors.New("config: trailing data after the JSON object")
	}
	if err := c.validate(getenv); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) validate(getenv func(string) string) error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("public_url must be an absolute https URL without query or fragment (cookies are Secure)")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	c.Public = u
	c.PublicURL = u.String()
	if c.CookieDomain != "" {
		d := strings.TrimPrefix(strings.ToLower(c.CookieDomain), ".")
		host := strings.ToLower(u.Hostname())
		if net.ParseIP(d) != nil || !strings.Contains(d, ".") || (host != d && !strings.HasSuffix(host, "."+d)) {
			return fmt.Errorf("cookie_domain %q must be a parent domain of the public_url host %q", c.CookieDomain, host)
		}
		c.CookieDomain = d
	}
	if c.Session.IdleTimeout == 0 {
		c.Session.IdleTimeout = Duration(DefaultIdle)
	}
	if c.Session.AbsoluteTimeout == 0 {
		c.Session.AbsoluteTimeout = Duration(DefaultAbsolute)
	}
	if c.Session.AbsoluteTimeout > Duration(MaxAbsolute) || c.Session.IdleTimeout > c.Session.AbsoluteTimeout ||
		c.Session.IdleTimeout < Duration(time.Minute) {
		return fmt.Errorf("session timeouts: idle must be at least 1m and at most absolute; absolute at most %s", MaxAbsolute)
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = Duration(DefaultSkew)
	}
	if c.ClockSkew > Duration(MaxSkew) {
		return fmt.Errorf("clock_skew must be at most %s", MaxSkew)
	}
	if c.UpstreamTokenTTL == 0 {
		c.UpstreamTokenTTL = Duration(DefaultTokenTTL)
	}
	if c.UpstreamTokenTTL < Duration(10*time.Second) || c.UpstreamTokenTTL > Duration(MaxTokenTTL) {
		return fmt.Errorf("upstream_token_ttl must be between 10s and %s", MaxTokenTTL)
	}
	if len(c.RedirectHosts) > maxListEntries {
		return errors.New("too many redirect_hosts")
	}

	if len(c.Providers) == 0 || len(c.Providers) > maxProviders {
		return fmt.Errorf("need 1 to %d providers", maxProviders)
	}
	providers := map[string]*Provider{}
	for i := range c.Providers {
		p := &c.Providers[i]
		if !idRe.MatchString(p.ID) {
			return fmt.Errorf("provider id %q must be 1-32 lower-case letters, digits or '-'", p.ID)
		}
		if providers[p.ID] != nil {
			return fmt.Errorf("duplicate provider id %q", p.ID)
		}
		providers[p.ID] = p
		if p.DisplayName == "" {
			p.DisplayName = p.ID
		}
		if len(p.DisplayName) > maxDisplayNameLen {
			return fmt.Errorf("provider %s: display_name longer than %d", p.ID, maxDisplayNameLen)
		}
		var err error
		switch p.Type {
		case ProviderOIDC:
			err = p.validateOIDC(getenv)
		case ProviderSAML:
			err = p.validateSAML()
		default:
			err = fmt.Errorf("type must be %q or %q", ProviderOIDC, ProviderSAML)
		}
		if err != nil {
			return fmt.Errorf("provider %s: %w", p.ID, err)
		}
	}

	if len(c.Apps) == 0 || len(c.Apps) > maxApps {
		return fmt.Errorf("need 1 to %d apps", maxApps)
	}
	apps := map[string]bool{}
	hosts := map[string]string{}
	for i := range c.Apps {
		a := &c.Apps[i]
		if !idRe.MatchString(a.ID) {
			return fmt.Errorf("app id %q must be 1-32 lower-case letters, digits or '-'", a.ID)
		}
		if apps[a.ID] {
			return fmt.Errorf("duplicate app id %q", a.ID)
		}
		apps[a.ID] = true
		if len(a.Hosts) == 0 {
			return fmt.Errorf("app %s: at least one host is required", a.ID)
		}
		for j, h := range a.Hosts {
			h = strings.ToLower(h)
			if h == "" || strings.ContainsAny(h, "/*@ ") {
				return fmt.Errorf("app %s: invalid host %q (use host or host:port)", a.ID, h)
			}
			if other, dup := hosts[h]; dup {
				return fmt.Errorf("host %q belongs to both %s and %s", h, other, a.ID)
			}
			hosts[h] = a.ID
			a.Hosts[j] = h
		}
		if len(a.Providers) == 0 {
			return fmt.Errorf("app %s: list the identity providers it accepts", a.ID)
		}
		for _, pid := range a.Providers {
			if providers[pid] == nil {
				return fmt.Errorf("app %s: unknown provider %q", a.ID, pid)
			}
		}
		if n := len(a.Allow.Emails) + len(a.Allow.EmailDomains) + len(a.Allow.Groups); n > maxListEntries {
			return fmt.Errorf("app %s: allow lists have more than %d entries", a.ID, maxListEntries)
		}
		for _, d := range a.Allow.EmailDomains {
			if d == "" || strings.ContainsAny(d, "@ ") || strings.HasPrefix(d, ".") {
				return fmt.Errorf("app %s: email domain %q should look like example.com", a.ID, d)
			}
		}
		for _, e := range a.Allow.Emails {
			if strings.Count(e, "@") != 1 {
				return fmt.Errorf("app %s: email %q is not an address", a.ID, e)
			}
		}
		if a.DefaultURL == "" {
			a.DefaultURL = "https://" + a.Hosts[0] + "/"
		}
		if du, err := url.Parse(a.DefaultURL); err != nil || du.Scheme != "https" || du.Host == "" {
			return fmt.Errorf("app %s: default_url must be an absolute https URL", a.ID)
		}
	}
	return nil
}

func (p *Provider) validateOIDC(getenv func(string) string) error {
	if p.IdPMetadataFile != "" || p.IdPMetadataURL != "" || p.SPKeyFile != "" || p.SPCertFile != "" || p.EntityID != "" ||
		p.SignRequests || p.NameIDFormat != "" || p.EmailAttribute != "" || p.NameAttribute != "" || p.GroupsAttribute != "" {
		return errors.New("SAML settings on an oidc provider")
	}
	if p.Issuer == "" || p.ClientID == "" {
		return errors.New("issuer and client_id are required")
	}
	if p.ClientSecretEnv != "" && p.ClientSecretFile != "" {
		return errors.New("set client_secret_env or client_secret_file, not both")
	}
	switch {
	case p.ClientSecretEnv != "":
		p.ClientSecret = getenv(p.ClientSecretEnv)
		if p.ClientSecret == "" {
			return fmt.Errorf("environment variable %s is empty", p.ClientSecretEnv)
		}
	case p.ClientSecretFile != "":
		b, err := os.ReadFile(p.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("client_secret_file: %w", err)
		}
		p.ClientSecret = strings.TrimSpace(string(b))
	}
	if p.PostLogoutRedirectURL != "" {
		if u, err := url.Parse(p.PostLogoutRedirectURL); err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("post_logout_redirect_url must be an absolute https URL")
		}
	}
	return nil
}

func (p *Provider) validateSAML() error {
	if p.Issuer != "" || p.ClientID != "" || p.ClientSecretEnv != "" || p.ClientSecretFile != "" || p.ClientAuth != "" ||
		len(p.Scopes) > 0 || len(p.Algorithms) > 0 || p.EmailClaim != "" || p.NameClaim != "" || p.GroupsClaim != "" ||
		p.Userinfo || len(p.TrustedAudiences) > 0 || p.PostLogoutRedirectURL != "" {
		return errors.New("OpenID Connect settings on a saml provider")
	}
	if (p.IdPMetadataFile == "") == (p.IdPMetadataURL == "") {
		return errors.New("set exactly one of idp_metadata_file and idp_metadata_url")
	}
	if (p.SPKeyFile == "") != (p.SPCertFile == "") {
		return errors.New("sp_key_file and sp_cert_file go together")
	}
	if p.SignRequests && p.SPKeyFile == "" {
		return errors.New("sign_requests needs sp_key_file and sp_cert_file")
	}
	return nil
}
