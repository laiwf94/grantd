// Package guard redacts secrets from tool results and bounds their size, and
// builds the redacted argument previews written to the audit log.
package guard

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/laiwf94/grantd/internal/agents/jsonrpc"
)

// Limits on configured guards.
const (
	MaxPatterns     = 32
	MaxPatternBytes = 512
	MaxOutputBytes  = 16 << 20
)

// Placeholder replaces every redacted match.
const Placeholder = "[REDACTED]"

const truncatedMarker = "…[truncated by toolgate]"

// builtins are well-known credential shapes. Each is anchored on a distinctive
// prefix so ordinary prose does not match.
var builtins = map[string]*regexp.Regexp{
	"aws_access_key_id": regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	"github_token":      regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`),
	"slack_token":       regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,250}\b`),
	"stripe_key":        regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247}\b`),
	"sk_prefixed_key":   regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
	"private_key":       regexp.MustCompile(`-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?-----END [A-Z ]{0,40}PRIVATE KEY-----`),
	"bearer_token":      regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`),
	"jwt":               regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`),
}

// BuiltinNames lists the names usable in a policy's output.redact.
func BuiltinNames() []string {
	names := make([]string, 0, len(builtins))
	for n := range builtins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Guard redacts and truncates one tool's results. A nil *Guard does nothing.
type Guard struct {
	patterns []*regexp.Regexp
	maxBytes int // 0: no limit
}

// New builds a guard from built-in pattern names, custom RE2 patterns and a
// byte limit on the result's payload (0 for none; see payloadSize).
func New(names, custom []string, maxBytes int) (*Guard, error) {
	if len(names)+len(custom) > MaxPatterns {
		return nil, fmt.Errorf("at most %d redaction patterns", MaxPatterns)
	}
	if maxBytes < 0 || maxBytes > MaxOutputBytes {
		return nil, fmt.Errorf("max_bytes must be from 0 to %d", MaxOutputBytes)
	}
	g := &Guard{maxBytes: maxBytes}
	for _, n := range names {
		re, ok := builtins[n]
		if !ok {
			return nil, fmt.Errorf("unknown redaction pattern %q (known: %s)", n, strings.Join(BuiltinNames(), ", "))
		}
		g.patterns = append(g.patterns, re)
	}
	for _, p := range custom {
		if p == "" || len(p) > MaxPatternBytes {
			return nil, fmt.Errorf("redaction patterns must be 1 to %d bytes", MaxPatternBytes)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redaction pattern %q: %v", p, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("redaction pattern %q matches the empty string", p)
		}
		g.patterns = append(g.patterns, re)
	}
	return g, nil
}

// Report says what Apply changed.
type Report struct {
	Redactions  int  `json:"redactions"`
	Truncated   bool `json:"truncated"`
	BytesBefore int  `json:"bytes_before"`
	BytesAfter  int  `json:"bytes_after"`
}

// Apply guards a decoded tools/call result in place and reports what it did.
// Every string and object key is scanned except base64 payloads: the data of
// image and audio content items and the blob of embedded resources.
func (g *Guard) Apply(result map[string]any) Report {
	var r Report
	r.BytesBefore = encodedSize(result)
	if g != nil {
		for k, v := range result {
			result[k] = g.redact(k, v, &r)
		}
		if g.maxBytes > 0 && payloadSize(result) > g.maxBytes {
			g.truncate(result, &r)
		}
	}
	r.BytesAfter = encodedSize(result)
	return r
}

// payloadSize is what max_bytes limits: the bytes of text content, plus the
// encoded size of other content items and of structured content. JSON framing
// around them is not counted.
func payloadSize(result map[string]any) int {
	n := 0
	if sc, ok := result["structuredContent"]; ok {
		n += encodedSize(sc)
	}
	items, _ := result["content"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		if text, ok := m["text"].(string); ok && m["type"] == "text" {
			n += len(text)
		} else {
			n += encodedSize(it)
		}
	}
	return n
}

func encodedSize(v any) int {
	b, err := jsonrpc.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

func (g *Guard) redact(key string, v any, r *Report) any {
	switch t := v.(type) {
	case string:
		return g.redactString(t, r)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if binaryPayload(t, k) {
				out[k] = e
				continue
			}
			nk := g.redactString(k, r) // keys can carry secrets too
			out[nk] = g.redact(nk, e, r)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = g.redact("", e, r)
		}
		return t
	default:
		return v
	}
}

// binaryPayload reports whether m[k] is base64 data that must not be
// rewritten: the data of an image or audio content item, or the blob of an
// embedded resource. Nothing else is exempt from redaction.
func binaryPayload(m map[string]any, k string) bool {
	switch k {
	case "data":
		typ, _ := m["type"].(string)
		return typ == "image" || typ == "audio"
	case "blob":
		_, hasURI := m["uri"]
		return hasURI
	}
	return false
}

func (g *Guard) redactString(s string, r *Report) string {
	for _, re := range g.patterns {
		s = re.ReplaceAllStringFunc(s, func(string) string {
			r.Redactions++
			return Placeholder
		})
	}
	return s
}

// truncate keeps the content items in order until the byte budget is used.
// Text is cut at a character boundary and marked; other items that do not fit
// are replaced by a marker. Structured content cannot be cut and stay valid
// against its schema, so it is dropped.
func (g *Guard) truncate(result map[string]any, r *Report) {
	r.Truncated = true
	delete(result, "structuredContent")
	items, _ := result["content"].([]any)
	budget := g.maxBytes
	out := make([]any, 0, len(items))
	for i, it := range items {
		m, _ := it.(map[string]any)
		if text, ok := m["text"].(string); ok && m["type"] == "text" {
			if len(text) <= budget {
				budget -= len(text)
				out = append(out, it)
				continue
			}
			cut := text[:budget]
			for !utf8.ValidString(cut) {
				cut = cut[:len(cut)-1]
			}
			m["text"] = cut + truncatedMarker
			out = appendOmitted(append(out, m), len(items)-i-1)
			break
		}
		if size := encodedSize(it); size <= budget {
			budget -= size
			out = append(out, it)
			continue
		}
		out = appendOmitted(out, len(items)-i)
		break
	}
	result["content"] = out
}

// previewGuard applies every built-in pattern.
var previewGuard = func() *Guard {
	g := &Guard{}
	for _, n := range BuiltinNames() {
		g.patterns = append(g.patterns, builtins[n])
	}
	return g
}()

func appendOmitted(out []any, n int) []any {
	if n == 0 {
		return out
	}
	return append(out, map[string]any{"type": "text",
		"text": fmt.Sprintf("[%d more content item(s) omitted by toolgate: output size limit]", n)})
}

// RedactText applies the guard's patterns and every built-in pattern to s,
// for text such as an upstream error message. A nil guard applies only the
// built-in patterns.
func (g *Guard) RedactText(s string) string {
	var r Report
	if g != nil {
		s = g.redactString(s, &r)
	}
	return previewGuard.redactString(s, &r)
}

// sensitiveKey matches argument names whose values are never previewed.
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie|session)`)

// Preview renders arguments for the audit log: values under sensitive-looking
// keys and every built-in secret shape are replaced, and the text is cut to
// maxChars characters.
func Preview(args any, maxChars int) string {
	var r Report
	v := previewValue(args, previewGuard, &r)
	b, err := jsonrpc.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if utf8.RuneCountInString(s) <= maxChars {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxChars]) + "…"
}

func previewValue(v any, g *Guard, r *Report) any {
	switch t := v.(type) {
	case string:
		return g.redactString(t, r)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			if sensitiveKey.MatchString(k) {
				m[k] = Placeholder
				continue
			}
			m[k] = previewValue(e, g, r)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, e := range t {
			a[i] = previewValue(e, g, r)
		}
		return a
	case json.Number, bool, nil:
		return t
	default:
		return fmt.Sprintf("%T", t)
	}
}
