package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity says whether a Problem stops the gateway from starting.
type Severity int

// Severities.
const (
	SeverityError Severity = iota
	SeverityWarning
)

func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// Problem is one finding about a configuration document.
type Problem struct {
	// Path is a JSON path into the document, such as $.apps[0].hosts[1].
	// For a missing field it names the object the field belongs in.
	Path string
	// Line and Column locate the value at Path in the file (1-based); 0
	// when the document could not be parsed far enough to know.
	Line, Column int
	Severity     Severity
	Message      string
}

func (p Problem) String() string { return p.Path + ": " + p.Message }

// Problems is every finding about a document, errors and warnings, in
// document order.
type Problems []Problem

// Count returns how many problems have severity s.
func (ps Problems) Count(s Severity) int {
	n := 0
	for _, p := range ps {
		if p.Severity == s {
			n++
		}
	}
	return n
}

// Err returns the errors as one error, or nil when there are none.
// Warnings never fail a load.
func (ps Problems) Err() error {
	var errs Problems
	for _, p := range ps {
		if p.Severity == SeverityError {
			errs = append(errs, p)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// Error joins the problems as "path: message; path: message".
func (ps Problems) Error() string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, "; ")
}

// Result is a checked document: the decoded configuration and every
// problem found in it. Later checks (files, network) add their problems
// through Errorf and Warnf so they are located the same way.
type Result struct {
	// Config holds everything that was well-formed, normalized as Parse
	// normalizes it. It is nil only when the document is not JSON at
	// all. A config with errors must not be used to serve.
	Config   *Config
	Problems Problems

	src []byte
	pos map[string]int // path -> byte offset of its value
	mu  sync.Mutex
}

// Add records a problem at path, locating it in the source. For a path
// that does not appear in the document (a missing field) it uses the
// position of the nearest enclosing value. It is safe for concurrent use.
func (r *Result) Add(sev Severity, path, format string, args ...any) {
	p := Problem{Path: path, Severity: sev, Message: fmt.Sprintf(format, args...)}
	for q := path; q != ""; q = parentPath(q) {
		if off, ok := r.pos[q]; ok {
			p.Line, p.Column = lineCol(r.src, off)
			break
		}
	}
	r.mu.Lock()
	r.Problems = append(r.Problems, p)
	r.mu.Unlock()
}

// Errorf records an error at path.
func (r *Result) Errorf(path, format string, args ...any) {
	r.Add(SeverityError, path, format, args...)
}

// Warnf records a warning at path.
func (r *Result) Warnf(path, format string, args ...any) {
	r.Add(SeverityWarning, path, format, args...)
}

// Sort orders the problems by position in the file; problems at the same
// position keep the order they were found in.
func (r *Result) Sort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	sort.SliceStable(r.Problems, func(i, j int) bool {
		a, b := r.Problems[i], r.Problems[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
}

// parentPath drops the last segment: $.a[0].b -> $.a[0] -> $.a -> $ -> "".
func parentPath(p string) string {
	if p == "$" {
		return ""
	}
	i := strings.LastIndexAny(p, ".[")
	if i <= 0 {
		return "$"
	}
	return p[:i]
}

func lineCol(src []byte, off int) (int, int) {
	off = min(off, len(src))
	before := src[:off]
	line := bytes.Count(before, []byte("\n")) + 1
	col := off - bytes.LastIndexByte(before, '\n')
	return line, col
}

var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func keyPath(parent, key string) string {
	if plainKey.MatchString(key) {
		return parent + "." + key
	}
	b, _ := json.Marshal(key)
	return parent + "[" + string(b) + "]"
}

func indexPath(parent string, i int) string { return fmt.Sprintf("%s[%d]", parent, i) }

var durationType = reflect.TypeFor[Duration]()

// errSyntax aborts the schema walk; the document cannot be read further.
var errSyntax = errors.New("syntax")

// schema walks the token stream of a document against the Config type. It
// reports unknown, duplicate and mistyped fields with their paths and
// returns the document with those removed, so the semantic checks can
// still run over everything that was well-formed.
type schema struct {
	dec *json.Decoder
	c   *Result
}

// start returns the offset of the next value, skipping what the decoder
// has not consumed yet between tokens (whitespace, ':' and ',').
func (s *schema) start() int {
	off := int(s.dec.InputOffset())
	for off < len(s.c.src) && strings.IndexByte(" \t\r\n:,", s.c.src[off]) >= 0 {
		off++
	}
	return off
}

func (s *schema) token() (json.Token, error) {
	tok, err := s.dec.Token()
	if err != nil {
		return nil, s.syntax(err)
	}
	return tok, nil
}

func (s *schema) syntax(err error) error {
	off := int(s.dec.InputOffset())
	var se *json.SyntaxError
	if errors.As(err, &se) {
		off = int(se.Offset)
	}
	msg := err.Error()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(msg, "unexpected end of JSON input") {
		msg = "unexpected end of file"
	}
	line, col := lineCol(s.c.src, off)
	s.c.Problems = append(s.c.Problems, Problem{Path: "$", Line: line, Column: col, Message: "invalid JSON: " + strings.TrimPrefix(msg, "json: ")})
	return errSyntax
}

// value reads one value of type t at path. keep is false when the value
// was wrong and has been dropped from the cleaned document.
func (s *schema) value(t reflect.Type, path string) (v any, keep bool, err error) {
	s.c.pos[path] = s.start()
	tok, err := s.token()
	if err != nil {
		return nil, false, err
	}
	if tok == nil {
		// null leaves the field unset, as if it were absent.
		return nil, false, nil
	}
	switch {
	case t == durationType:
		str, ok := tok.(string)
		if !ok {
			return s.mismatch(tok, path, `a duration string like "90s" or "8h"`)
		}
		if d, err := time.ParseDuration(str); err != nil || d < 0 {
			s.c.Errorf(path, `invalid duration %q (use a string like "90s" or "8h")`, str)
			return nil, false, nil
		}
		return str, true, nil
	case t.Kind() == reflect.String:
		if str, ok := tok.(string); ok {
			return str, true, nil
		}
		return s.mismatch(tok, path, "a string")
	case t.Kind() == reflect.Bool:
		if b, ok := tok.(bool); ok {
			return b, true, nil
		}
		return s.mismatch(tok, path, "true or false")
	case t.Kind() == reflect.Slice:
		if tok != json.Delim('[') {
			return s.mismatch(tok, path, "an array")
		}
		out := []any{}
		for i := 0; s.dec.More(); i++ {
			ev, ok, err := s.value(t.Elem(), indexPath(path, i))
			if err != nil {
				return nil, false, err
			}
			if ok {
				out = append(out, ev)
			}
		}
		if _, err := s.token(); err != nil {
			return nil, false, err
		}
		return out, true, nil
	case t.Kind() == reflect.Struct:
		if tok != json.Delim('{') {
			return s.mismatch(tok, path, "an object")
		}
		return s.object(t, path)
	}
	panic("config: no schema rule for " + t.String())
}

func (s *schema) object(t reflect.Type, path string) (any, bool, error) {
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			fields[name] = f.Type
		}
	}
	out := map[string]any{}
	seen := map[string]bool{}
	for s.dec.More() {
		keyOff := s.start()
		tok, err := s.token()
		if err != nil {
			return nil, false, err
		}
		key := tok.(string) // object keys are always strings
		kp := keyPath(path, key)
		s.c.pos[kp] = keyOff
		ft, known := fields[key]
		switch {
		case seen[key]:
			s.c.Errorf(kp, "duplicate field %q", key)
			known = false
		case !known:
			s.c.Errorf(kp, "unknown field%s", suggest(key, fields))
		}
		seen[key] = true
		if !known {
			if err := s.skip(); err != nil {
				return nil, false, err
			}
			continue
		}
		v, ok, err := s.value(ft, kp)
		if err != nil {
			return nil, false, err
		}
		if ok {
			out[key] = v
		}
	}
	if _, err := s.token(); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// suggest names the field the author probably meant: one that differs
// only in case, or is one edit away.
func suggest(key string, fields map[string]reflect.Type) string {
	var best []string
	for name := range fields {
		if strings.EqualFold(name, key) || editDistance(name, key) <= 2 {
			best = append(best, name)
		}
	}
	if len(best) == 0 {
		return ""
	}
	sort.Strings(best)
	return fmt.Sprintf(" (did you mean %q?)", best[0])
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func (s *schema) mismatch(tok json.Token, path, want string) (any, bool, error) {
	got := "a string"
	switch tok.(type) {
	case json.Delim:
		got = "an object"
		if tok == json.Delim('[') {
			got = "an array"
		}
	case bool:
		got = "a boolean"
	case json.Number:
		got = "a number"
	}
	s.c.Errorf(path, "must be %s, not %s", want, got)
	if d, ok := tok.(json.Delim); ok {
		return nil, false, s.skipRest(d)
	}
	return nil, false, nil
}

// skip consumes one whole value.
func (s *schema) skip() error {
	tok, err := s.token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok {
		return s.skipRest(d)
	}
	return nil
}

// skipRest consumes the rest of an array or object whose opening
// delimiter has been read.
func (s *schema) skipRest(json.Delim) error {
	for depth := 1; depth > 0; {
		tok, err := s.token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

// Check decodes and validates a configuration document and returns every
// problem it finds, each with its JSON path and position. getenv resolves
// client_secret_env; nil treats every variable as empty.
func Check(b []byte, getenv func(string) string) *Result {
	r := &Result{src: b, pos: map[string]int{}}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	s := &schema{dec: dec, c: r}
	clean, keep, err := s.value(reflect.TypeFor[Config](), "$")
	if err != nil {
		r.Sort()
		return r
	}
	if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
		line, col := lineCol(b, s.start())
		r.Problems = append(r.Problems, Problem{Path: "$", Line: line, Column: col, Message: "trailing data after the JSON object"})
	}
	if !keep {
		// Valid JSON but not an object, or null: the mismatch is
		// reported; check an empty config so missing required fields
		// are listed too.
		clean = map[string]any{}
	}
	cleaned, merr := json.Marshal(clean)
	if merr != nil {
		panic("config: re-encoding a decoded document: " + merr.Error())
	}
	var cfg Config
	if uerr := json.Unmarshal(cleaned, &cfg); uerr != nil {
		panic("config: decoding a schema-checked document: " + uerr.Error())
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	cfg.validate(getenv, r)
	r.Config = &cfg
	r.Sort()
	return r
}

// Snapshot returns a copy of the problems recorded so far. It is safe for
// concurrent use with Add.
func (r *Result) Snapshot() Problems {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append(Problems(nil), r.Problems...)
}
