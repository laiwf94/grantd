// Package schema validates tool-call arguments against a small, closed subset
// of JSON Schema (draft 2020-12 semantics) plus two keywords for arguments
// that name files and URLs.
//
// Supported keywords: type, enum, pattern, minLength, maxLength, minimum,
// maximum, required, properties, additionalProperties (boolean only), items,
// minItems, maxItems, and the annotations title, description and $comment.
// Extensions:
//
//	x-path-prefix    ["/srv/data", "reports/"]  string must be a canonical path under one prefix
//	x-allowed-hosts  ["api.example.com", "*.example.org", "localhost:8443"]  string must be an http(s) URL to one of these hosts
//
// Any other keyword is a compile error. A misspelt "maxLenght" in a policy
// must fail loudly, not silently allow everything.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laiwf94/grantd/internal/agents/jsonrpc"
)

// Compile limits. They bound the cost of compiling and evaluating a schema
// that came from a policy file.
const (
	MaxDepth         = 32
	MaxNodes         = 2048
	MaxEnum          = 256
	MaxProperties    = 256
	MaxPatternBytes  = 1024
	MaxPrefixes      = 64
	MaxHosts         = 256
	MaxPathBytes     = 4096
	MaxURLBytes      = 8192
	maxLengthKeyword = 1 << 20
)

type typeSet uint8

const (
	tNull typeSet = 1 << iota
	tBoolean
	tObject
	tArray
	tNumber
	tString
	tInteger
)

var typeNames = map[string]typeSet{"null": tNull, "boolean": tBoolean, "object": tObject,
	"array": tArray, "number": tNumber, "string": tString, "integer": tInteger}

// Schema is a compiled schema. It is immutable and safe for concurrent use.
type Schema struct {
	types        typeSet // 0 means any type
	enum         []string
	pattern      *regexp.Regexp
	minLength    int
	maxLength    int // -1: none
	minimum      *float64
	maximum      *float64
	required     []string
	properties   map[string]*Schema
	closed       bool // additionalProperties: false
	items        *Schema
	minItems     int
	maxItems     int // -1: none
	pathPrefixes []string
	hosts        []hostRule
}

type hostRule struct {
	host     string // lower case, without "*."
	wildcard bool   // matches subdomains of host, not host itself
	port     string // "" means the scheme's default port
}

// Compile parses and compiles a schema document.
func Compile(raw []byte) (*Schema, error) {
	v, err := jsonrpc.DecodeValue(raw)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return CompileValue(v)
}

// CompileValue compiles an already decoded schema (numbers as json.Number).
func CompileValue(v any) (*Schema, error) {
	nodes := 0
	return compile(v, "$", 0, &nodes)
}

func compile(v any, at string, depth int, nodes *int) (*Schema, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("schema %s: nested deeper than %d levels", at, MaxDepth)
	}
	if *nodes++; *nodes > MaxNodes {
		return nil, fmt.Errorf("schema: more than %d subschemas", MaxNodes)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema %s: must be an object", at)
	}
	s := &Schema{maxLength: -1, maxItems: -1}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic error messages
	for _, k := range keys {
		val := obj[k]
		bad := func(format string, args ...any) error {
			return fmt.Errorf("schema %s: %s %s", at, k, fmt.Sprintf(format, args...))
		}
		switch k {
		case "title", "description", "$comment":
			if _, ok := val.(string); !ok {
				return nil, bad("must be a string")
			}
		case "type":
			names, err := stringList(val, true)
			if err != nil || len(names) == 0 {
				return nil, bad("must be a type name or a non-empty array of type names")
			}
			for _, n := range names {
				t, ok := typeNames[n]
				if !ok {
					return nil, bad("has unknown type %q", n)
				}
				if s.types&t != 0 {
					return nil, bad("repeats %q", n)
				}
				s.types |= t
			}
		case "enum":
			arr, ok := val.([]any)
			if !ok || len(arr) == 0 || len(arr) > MaxEnum {
				return nil, bad("must be an array of 1 to %d values", MaxEnum)
			}
			seen := map[string]bool{}
			for _, e := range arr {
				c, err := canonical(e)
				if err != nil {
					return nil, bad("value: %v", err)
				}
				if seen[c] {
					return nil, bad("repeats %s", c)
				}
				seen[c] = true
				s.enum = append(s.enum, c)
			}
		case "pattern":
			p, ok := val.(string)
			if !ok || len(p) > MaxPatternBytes {
				return nil, bad("must be a string of at most %d bytes", MaxPatternBytes)
			}
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, bad("is not a valid RE2 expression: %v", err)
			}
			s.pattern = re
		case "minLength", "maxLength", "minItems", "maxItems":
			n, err := count(val)
			if err != nil {
				return nil, bad("%v", err)
			}
			switch k {
			case "minLength":
				s.minLength = n
			case "maxLength":
				s.maxLength = n
			case "minItems":
				s.minItems = n
			case "maxItems":
				s.maxItems = n
			}
		case "minimum", "maximum":
			f, err := number(val)
			if err != nil {
				return nil, bad("%v", err)
			}
			if k == "minimum" {
				s.minimum = &f
			} else {
				s.maximum = &f
			}
		case "required":
			names, err := stringList(val, false)
			if err != nil {
				return nil, bad("must be an array of property names")
			}
			if dup := firstDuplicate(names); dup != "" {
				return nil, bad("repeats %q", dup)
			}
			s.required = names
		case "properties":
			props, ok := val.(map[string]any)
			if !ok || len(props) > MaxProperties {
				return nil, bad("must be an object with at most %d entries", MaxProperties)
			}
			s.properties = make(map[string]*Schema, len(props))
			for name, sub := range props {
				c, err := compile(sub, at+"."+name, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				s.properties[name] = c
			}
		case "additionalProperties":
			b, ok := val.(bool)
			if !ok {
				return nil, bad("must be a boolean (subschemas are not supported)")
			}
			s.closed = !b
		case "items":
			c, err := compile(val, at+"[]", depth+1, nodes)
			if err != nil {
				return nil, err
			}
			s.items = c
		case "x-path-prefix":
			list, err := stringList(val, false)
			if err != nil || len(list) == 0 || len(list) > MaxPrefixes {
				return nil, bad("must be an array of 1 to %d paths", MaxPrefixes)
			}
			for _, p := range list {
				if err := checkCanonicalPath(p); err != nil {
					return nil, bad("entry %q: %v", p, err)
				}
				if len(p) > 1 {
					p = strings.TrimSuffix(p, "/")
				}
				s.pathPrefixes = append(s.pathPrefixes, p)
			}
		case "x-allowed-hosts":
			list, err := stringList(val, false)
			if err != nil || len(list) == 0 || len(list) > MaxHosts {
				return nil, bad("must be an array of 1 to %d hosts", MaxHosts)
			}
			for _, h := range list {
				r, err := parseHostRule(h)
				if err != nil {
					return nil, bad("entry %q: %v", h, err)
				}
				s.hosts = append(s.hosts, r)
			}
		default:
			return nil, fmt.Errorf("schema %s: unsupported keyword %q", at, k)
		}
	}
	if s.maxLength >= 0 && s.minLength > s.maxLength {
		return nil, fmt.Errorf("schema %s: minLength is greater than maxLength", at)
	}
	if s.maxItems >= 0 && s.minItems > s.maxItems {
		return nil, fmt.Errorf("schema %s: minItems is greater than maxItems", at)
	}
	if s.minimum != nil && s.maximum != nil && *s.minimum > *s.maximum {
		return nil, fmt.Errorf("schema %s: minimum is greater than maximum", at)
	}
	if (s.pathPrefixes != nil || s.hosts != nil) && s.types != 0 && s.types&tString == 0 {
		return nil, fmt.Errorf("schema %s: x-path-prefix and x-allowed-hosts apply to strings", at)
	}
	if s.pathPrefixes != nil && s.hosts != nil {
		return nil, fmt.Errorf("schema %s: use x-path-prefix or x-allowed-hosts, not both", at)
	}
	return s, nil
}

func stringList(v any, allowSingle bool) ([]string, error) {
	if s, ok := v.(string); ok && allowSingle {
		return []string{s}, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, errors.New("not a string")
		}
		out = append(out, s)
	}
	return out, nil
}

func firstDuplicate(list []string) string {
	seen := map[string]bool{}
	for _, s := range list {
		if seen[s] {
			return s
		}
		seen[s] = true
	}
	return ""
}

func count(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("must be a non-negative integer")
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil || i < 0 || i > maxLengthKeyword {
		return 0, fmt.Errorf("must be an integer from 0 to %d", maxLengthKeyword)
	}
	return int(i), nil
}

func number(v any) (float64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("must be a number")
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsInf(f, 0) {
		return 0, errors.New("must be a finite number")
	}
	return f, nil
}

func canonical(v any) (string, error) {
	b, err := jsonrpc.Canonical(normalizeNumbers(v))
	return string(b), err
}

// normalizeNumbers rewrites numbers in their shortest float form so that 1,
// 1.0 and 1e0 compare equal in enum, as JSON Schema requires.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(t.String(), 64)
		if err != nil {
			return t
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64))
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = normalizeNumbers(e)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, e := range t {
			a[i] = normalizeNumbers(e)
		}
		return a
	default:
		return v
	}
}

// UsesAllowLists reports whether the schema, or any subschema, uses
// x-path-prefix or x-allowed-hosts.
func (s *Schema) UsesAllowLists() bool {
	if s.pathPrefixes != nil || s.hosts != nil {
		return true
	}
	if s.items != nil && s.items.UsesAllowLists() {
		return true
	}
	for _, p := range s.properties {
		if p.UsesAllowLists() {
			return true
		}
	}
	return false
}

// ValidationError says where and why a value failed.
type ValidationError struct {
	Path string // JSON path, e.g. $.files[2]
	Msg  string
}

func (e *ValidationError) Error() string { return e.Path + ": " + e.Msg }

// Validate checks a decoded value (numbers as json.Number). It returns the
// first failure as a *ValidationError.
func (s *Schema) Validate(v any) error { return s.validate(v, "$") }

func typeOf(v any) typeSet {
	switch t := v.(type) {
	case nil:
		return tNull
	case bool:
		return tBoolean
	case map[string]any:
		return tObject
	case []any:
		return tArray
	case string:
		return tString
	case json.Number:
		f, err := strconv.ParseFloat(t.String(), 64)
		if err == nil && !math.IsInf(f, 0) && f == math.Trunc(f) {
			return tNumber | tInteger
		}
		return tNumber
	default:
		return 0
	}
}

func typeName(t typeSet) string {
	var names []string
	for n, bit := range typeNames {
		if t&bit != 0 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return strings.Join(names, " or ")
}

func (s *Schema) validate(v any, at string) error {
	fail := func(format string, args ...any) error {
		return &ValidationError{Path: at, Msg: fmt.Sprintf(format, args...)}
	}
	t := typeOf(v)
	if t == 0 {
		return fail("unsupported value type %T", v)
	}
	if s.types != 0 && s.types&t == 0 {
		return fail("must be %s", typeName(s.types))
	}
	if (s.pathPrefixes != nil || s.hosts != nil) && t != tString {
		// Without this, ["http://169.254.169.254/"] would pass a host check
		// that only looks at strings, and an upstream that stringifies its
		// argument would fetch it.
		return fail("must be string")
	}
	if s.enum != nil {
		c, err := canonical(v)
		if err != nil {
			return fail("cannot compare value: %v", err)
		}
		found := false
		for _, e := range s.enum {
			if e == c {
				found = true
				break
			}
		}
		if !found {
			return fail("must be one of the allowed values")
		}
	}
	switch val := v.(type) {
	case string:
		n := utf8.RuneCountInString(val)
		if n < s.minLength {
			return fail("must be at least %d characters", s.minLength)
		}
		if s.maxLength >= 0 && n > s.maxLength {
			return fail("must be at most %d characters", s.maxLength)
		}
		if s.pattern != nil && !s.pattern.MatchString(val) {
			return fail("does not match the required pattern")
		}
		if s.pathPrefixes != nil {
			if err := s.checkPath(val); err != nil {
				return fail("%v", err)
			}
		}
		if s.hosts != nil {
			if err := s.checkURL(val); err != nil {
				return fail("%v", err)
			}
		}
	case json.Number:
		f, err := strconv.ParseFloat(val.String(), 64)
		if err != nil {
			return fail("is not a usable number")
		}
		if s.minimum != nil && f < *s.minimum {
			return fail("must be at least %s", strconv.FormatFloat(*s.minimum, 'g', -1, 64))
		}
		if s.maximum != nil && f > *s.maximum {
			return fail("must be at most %s", strconv.FormatFloat(*s.maximum, 'g', -1, 64))
		}
	case []any:
		if len(val) < s.minItems {
			return fail("must have at least %d items", s.minItems)
		}
		if s.maxItems >= 0 && len(val) > s.maxItems {
			return fail("must have at most %d items", s.maxItems)
		}
		if s.items != nil {
			for i, e := range val {
				if err := s.items.validate(e, at+"["+strconv.Itoa(i)+"]"); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		for _, r := range s.required {
			if _, ok := val[r]; !ok {
				return fail("missing required property %q", r)
			}
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys) // report the same first error every time
		for _, k := range keys {
			sub, ok := s.properties[k]
			if !ok {
				if s.closed {
					return fail("property %q is not allowed", k)
				}
				continue
			}
			if err := sub.validate(val[k], childPath(at, k)); err != nil {
				return err
			}
		}
	}
	return nil
}

var simpleKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func childPath(at, k string) string {
	if simpleKey.MatchString(k) {
		return at + "." + k
	}
	b, _ := jsonrpc.Marshal(k)
	return at + "[" + string(b) + "]"
}

// checkCanonicalPath accepts only paths whose lexical form is already clean:
// no "." or ".." segments, no repeated or (except a trailing one) redundant
// slashes, no backslashes or control characters.
//
// Lexical cleaning is not what a file system does when a symlink sits before a
// "..", so rather than clean and compare, non-canonical input is refused.
func checkCanonicalPath(p string) error {
	if p == "" || len(p) > MaxPathBytes {
		return fmt.Errorf("must be 1 to %d bytes", MaxPathBytes)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return errors.New("must not contain control characters or backslashes")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return errors.New(`must not contain ".." segments`)
		}
	}
	trimmed := p
	if len(p) > 1 {
		trimmed = strings.TrimSuffix(p, "/")
	}
	if path.Clean(trimmed) != trimmed {
		return errors.New("must be in canonical form (no '.' segments or repeated slashes)")
	}
	return nil
}

func (s *Schema) checkPath(p string) error {
	if err := checkCanonicalPath(p); err != nil {
		return fmt.Errorf("path %v", err)
	}
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		// "secrets/.env/" names the same file as "secrets/.env" to most path
		// libraries, but not to a pattern anchored at the end.
		return errors.New(`path must not end with "/"`)
	}
	for _, pre := range s.pathPrefixes {
		if pre == "/" {
			if strings.HasPrefix(p, "/") {
				return nil // "/" allows every absolute path
			}
			continue
		}
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return nil
		}
	}
	return errors.New("path is outside the allowed directories")
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func parseHostRule(entry string) (hostRule, error) {
	e := strings.ToLower(entry)
	var r hostRule
	if h, p, err := net.SplitHostPort(e); err == nil {
		if !validPort(p) {
			return r, errors.New("port must be 1 to 65535")
		}
		e, r.port = h, p
	}
	if rest, ok := strings.CutPrefix(e, "*."); ok {
		e, r.wildcard = rest, true
	}
	if net.ParseIP(e) != nil {
		if r.wildcard {
			return r, errors.New("an IP address cannot have a wildcard")
		}
	} else if !hostnameRe.MatchString(e) {
		return r, errors.New("must be a host name, *.domain, or an IP address, with an optional :port")
	}
	r.host = e
	return r, nil
}

func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

// checkURL accepts an absolute http or https URL whose host is allow-listed.
//
// URL parsers disagree on odd input (backslashes, "@" in odd places, spaces),
// which is the classic way to make a validator and a fetcher see different
// hosts. Such input is refused outright instead of being interpreted.
func (s *Schema) checkURL(raw string) error {
	if len(raw) > MaxURLBytes {
		return fmt.Errorf("URL is longer than %d bytes", MaxURLBytes)
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r == '\\' || r > 0x7e {
			return errors.New("URL must be printable ASCII without spaces or backslashes")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("URL does not parse")
	}
	scheme := u.Scheme
	if scheme != "http" && scheme != "https" {
		return errors.New("URL must use http or https")
	}
	if u.Opaque != "" || u.Host == "" || u.User != nil || strings.Contains(u.Host, "@") {
		return errors.New("URL must have a host and no user information")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port != "" && !validPort(port) {
		return errors.New("URL port must be 1 to 65535")
	}
	if net.ParseIP(host) == nil && !hostnameRe.MatchString(host) {
		return errors.New("URL host is not a valid host name")
	}
	defaultPort := map[string]string{"http": "80", "https": "443"}[scheme]
	effective := port
	if effective == "" {
		effective = defaultPort
	}
	for _, r := range s.hosts {
		hostOK := !r.wildcard && r.host == host || r.wildcard && strings.HasSuffix(host, "."+r.host)
		portOK := r.port == effective || r.port == "" && effective == defaultPort
		if hostOK && portOK {
			return nil
		}
	}
	return errors.New("URL host is not in the allowed list")
}
