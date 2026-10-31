// Package redirect validates return URLs so a login can only send the browser
// back to hosts this deployment protects (no open redirects, RFC 9700
// section 4.11).
package redirect

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// MaxLength bounds accepted return URLs.
const MaxLength = 2048

// ErrNotAllowed is returned for any URL that is rejected.
var ErrNotAllowed = errors.New("redirect: return URL not allowed")

// Validator checks return URLs against an allow-list of hosts.
type Validator struct {
	exact    map[string]bool // "host:port", lower case
	suffixes []string        // ".example.com:443"
	base     *url.URL        // for relative paths
}

// New builds a validator. Each pattern is "host", "host:port" or
// "*.domain[:port]"; without a port, 443 is implied. Relative return paths
// are resolved against base, whose host is always allowed.
func New(patterns []string, base *url.URL) (*Validator, error) {
	if base == nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("redirect: base must be an absolute https URL")
	}
	v := &Validator{exact: map[string]bool{}, base: base}
	v.exact[withPort(strings.ToLower(base.Host))] = true
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if rest, ok := strings.CutPrefix(p, "*."); ok {
			if !validHostPort(rest) {
				return nil, fmt.Errorf("redirect: invalid host pattern %q", p)
			}
			v.suffixes = append(v.suffixes, "."+withPort(rest))
			continue
		}
		if !validHostPort(p) {
			return nil, fmt.Errorf("redirect: invalid host %q", p)
		}
		v.exact[withPort(p)] = true
	}
	return v, nil
}

func withPort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return hostport + ":443"
}

func validHostPort(hp string) bool {
	host := hp
	if h, port, err := net.SplitHostPort(hp); err == nil {
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return false
		}
		host = h
	}
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// HostAllowed reports whether host ("name" or "name:port") is on the list.
func (v *Validator) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	if !validHostPort(host) {
		return false
	}
	hp := withPort(host)
	if v.exact[hp] {
		return true
	}
	for _, s := range v.suffixes {
		if strings.HasSuffix(hp, s) && len(hp) > len(s) {
			return true
		}
	}
	return false
}

// Validate returns the canonical absolute form of raw if it is a safe return
// URL: https, no user info, an allowed host, and nothing a browser would read
// differently from Go (backslashes, control characters, whitespace,
// percent-encoded hosts, scheme-relative "//host" paths).
func (v *Validator) Validate(raw string) (string, error) {
	if raw == "" || len(raw) > MaxLength {
		return "", ErrNotAllowed
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c <= 0x20 || c == 0x7f || c == '\\' {
			return "", ErrNotAllowed
		}
	}
	var u *url.URL
	if raw[0] == '/' {
		if len(raw) > 1 && raw[1] == '/' {
			return "", ErrNotAllowed
		}
		ref, err := url.Parse(raw)
		if err != nil || ref.Scheme != "" || ref.Host != "" {
			return "", ErrNotAllowed
		}
		u = v.base.ResolveReference(ref)
	} else {
		var err error
		if u, err = url.Parse(raw); err != nil {
			return "", ErrNotAllowed
		}
		// Reject what url.Parse would decode in the host.
		rest, ok := strings.CutPrefix(raw, u.Scheme+"://")
		if !ok {
			return "", ErrNotAllowed
		}
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		if strings.ContainsRune(rest, '%') {
			return "", ErrNotAllowed
		}
	}
	if u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", ErrNotAllowed
	}
	if !v.HostAllowed(u.Host) {
		return "", ErrNotAllowed
	}
	out := u.String()
	if len(out) > MaxLength {
		return "", ErrNotAllowed
	}
	return out, nil
}

// CheckHost reports whether p is a valid allow-list entry: "host" or
// "host:port", or with wildcard set also "*.domain[:port]". It accepts
// exactly what New accepts.
func CheckHost(p string, wildcard bool) error {
	p = strings.ToLower(strings.TrimSpace(p))
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		if !wildcard {
			return fmt.Errorf("wildcard %q is not allowed here", p)
		}
		p = rest
	}
	if !validHostPort(p) {
		return fmt.Errorf("invalid host %q (use host or host:port)", p)
	}
	return nil
}

// Canonical returns host:port in lower case, adding the implied :443.
func Canonical(hostport string) string { return withPort(strings.ToLower(hostport)) }
