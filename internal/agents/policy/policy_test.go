package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/grantd/internal/agents/jsonrpc"
)

const example = `{
  "version": 1,
  "rules": [
    {"id": "no-secrets", "effect": "deny", "agents": ["*"], "upstreams": ["fs"], "tools": ["read_file"],
     "arguments": {"required": ["path"], "properties": {"path": {"pattern": "\\.env$"}}}},
    {"id": "no-admin", "effect": "deny", "agents": ["*"], "upstreams": ["*"], "tools": ["admin_*"]},
    {"id": "fs-read", "description": "read the sandbox", "effect": "allow", "scopes": ["files:read"], "upstreams": ["fs"], "tools": ["read_file", "list_dir"],
     "arguments": {"type": "object", "required": ["path"], "additionalProperties": false,
                   "properties": {"path": {"type": "string", "maxLength": 256, "x-path-prefix": ["/sandbox"]}}},
     "output": {"redact": ["aws_access_key_id"], "max_bytes": 4096}},
    {"id": "web", "effect": "allow", "agents": ["alice-bot"], "upstreams": ["web"], "tools": ["*"],
     "arguments": {"properties": {"url": {"type": "string", "x-allowed-hosts": ["api.example.com"]}}}},
    {"id": "deploy", "effect": "allow", "agents": ["alice-bot"], "upstreams": ["*"], "tools": ["deploy"], "requires_approval": true},
    {"id": "admin-any", "effect": "allow", "agents": ["root-bot"], "upstreams": ["*"], "tools": ["*"]}
  ]
}`

func args(t testing.TB, s string) any {
	t.Helper()
	v, err := jsonrpc.DecodeValue([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEvaluate(t *testing.T) {
	p, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	alice := Subject{AgentID: "alice-bot", Scopes: []string{"files:read"}}
	bob := Subject{AgentID: "bob-bot"}
	root := Subject{AgentID: "root-bot"}
	cases := []struct {
		s          Subject
		up, tool   string
		args       string
		allowed    bool
		rule       string
		constraint string
		approval   bool
		reason     string
	}{
		{alice, "fs", "read_file", `{"path":"/sandbox/a.txt"}`, true, "fs-read", "", false, "allowed by rule fs-read"},
		{alice, "fs", "list_dir", `{"path":"/sandbox"}`, true, "fs-read", "", false, ""},
		{alice, "fs", "read_file", `{"path":"/sandbox/.env"}`, false, "no-secrets", "", false, "rule no-secrets forbids this call"},
		{alice, "fs", "read_file", `{"path":"../../etc/passwd"}`, false, DefaultDenyID, "fs-read", false, `arguments rejected by rule fs-read: $.path: path must not contain ".." segments`},
		{alice, "fs", "read_file", `{"path":"/etc/passwd"}`, false, DefaultDenyID, "fs-read", false, ""},
		{alice, "fs", "read_file", `{}`, false, DefaultDenyID, "fs-read", false, ""},
		{alice, "fs", "read_file", `null`, false, DefaultDenyID, "fs-read", false, `arguments rejected by rule fs-read: $: missing required property "path"`},
		{alice, "fs", "write_file", `{"path":"/sandbox/a"}`, false, DefaultDenyID, "", false, "no rule allows this call"},
		{bob, "fs", "read_file", `{"path":"/sandbox/a.txt"}`, false, DefaultDenyID, "", false, ""},
		{alice, "web", "http_get", `{"url":"https://api.example.com/x"}`, true, "web", "", false, ""},
		{alice, "web", "http_get", `{"url":"http://169.254.169.254/"}`, false, DefaultDenyID, "web", false, ""},
		{alice, "web", "admin_reset", `{}`, false, "no-admin", "", false, ""},
		{alice, "fs", "deploy", `{}`, true, "deploy", "", true, ""},
		{alice, "other", "deploy", `{}`, true, "deploy", "", true, ""},
		{root, "other", "anything", `{}`, true, "admin-any", "", false, ""},
		{root, "x", "admin_x", `{}`, false, "no-admin", "", false, ""},
	}
	for _, c := range cases {
		var a any
		if c.args != "null" {
			a = args(t, c.args)
		}
		d := p.Evaluate(c.s, c.up, c.tool, a)
		if d.Allowed != c.allowed || d.RuleID != c.rule || d.ConstraintRuleID != c.constraint || d.RequiresApproval != c.approval {
			t.Errorf("%s %s.%s %s: got %+v", c.s.AgentID, c.up, c.tool, c.args, d)
		}
		if c.reason != "" && d.Reason != c.reason {
			t.Errorf("%s.%s %s: reason %q, want %q", c.up, c.tool, c.args, d.Reason, c.reason)
		}
	}
	if d := p.Evaluate(alice, "fs", "read_file", args(t, `{"path":"/sandbox/a"}`)); d.Output == nil {
		t.Fatal("output guard not attached")
	}
	vis := []struct {
		s        Subject
		up, tool string
		want     bool
	}{
		{alice, "fs", "read_file", true}, // denied only for some arguments
		{alice, "fs", "write_file", false},
		{alice, "web", "anything", true},
		{alice, "web", "admin_x", false}, // unconditional deny
		{bob, "fs", "read_file", false},
		{root, "zzz", "tool", true},
	}
	for _, v := range vis {
		if got := p.Visible(v.s, v.up, v.tool); got != v.want {
			t.Errorf("Visible(%s, %s.%s) = %v", v.s.AgentID, v.up, v.tool, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	rule := func(extra string) string {
		return `{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"]` + extra + `}]}`
	}
	cases := map[string]string{
		`{"version":2,"rules":[]}`:                    "version must be 1",
		`{"version":1,"rules":[],"extra":1}`:          "unknown field",
		`{"version":1,"rules":[{"id":"r","id":"s"}]}`: "duplicate object key",
		`[]`: "cannot unmarshal",
		`{"version":1,"rules":[{"id":"bad id","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"]}]}`:       "id must be",
		`{"version":1,"rules":[{"id":"default-deny","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"]}]}`: "id must be",
		`{"version":1,"rules":[{"id":"r","effect":"maybe","agents":["a"],"upstreams":["u"],"tools":["t"]}]}`:            "effect must be",
		`{"version":1,"rules":[{"id":"r","effect":"allow","upstreams":["u"],"tools":["t"]}]}`:                           "name the subject",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"tools":["t"]}]}`:                              "upstreams must not be empty",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":[]}]}`:               "tools must have",
		rule(`,"arguments":{"maxLenght":1}`):                       "unsupported keyword",
		rule(`,"output":{"redact":["nope"]}`):                      "unknown redaction pattern",
		rule(`,"description":"` + strings.Repeat("d", 1025) + `"`): "description is longer",
		`{"version":1,"rules":[{"id":"r","effect":"deny","agents":["a"],"upstreams":["u"],"tools":["t"],"requires_approval":true}]}`:                                                   "only to allow rules",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a b"],"upstreams":["u"],"tools":["t"]}]}`:                                                                         "agents entry",
		`{"version":1,"rules":[{"id":"r","effect":"allow","scopes":["*"],"upstreams":["u"],"tools":["t"]}]}`:                                                                           "scopes cannot be",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["*","a"],"upstreams":["u"],"tools":["t"]}]}`:                                                                       "already matches everything",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["Up"],"tools":["t"]}]}`:                                                                          "upstreams entry",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["a*b"]}]}`:                                                                         "must be a tool name",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["**"]}]}`:                                                                          "must be a tool name",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":[""]}]}`:                                                                            "must be a tool name",
		`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"]},{"id":"r","effect":"deny","agents":["a"],"upstreams":["u"],"tools":["t"]}]}`: "used twice",
		`{"version":1,"rules":[{"id":"r","effect":"deny","agents":["a"],"upstreams":["u"],"tools":["t"],"arguments":{"properties":{"u":{"x-allowed-hosts":["169.254.169.254"]}}}}]}`:   "cannot be used in deny rules",
	}
	for src, want := range cases {
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.80s: got %v, want %q", src, err, want)
		}
	}
	big := make([]string, MaxSelectorItems+1)
	for i := range big {
		big[i] = fmt.Sprintf("%q", fmt.Sprintf("a%d", i))
	}
	if _, err := Parse([]byte(`{"version":1,"rules":[{"id":"r","effect":"allow","agents":[` + strings.Join(big, ",") + `],"upstreams":["u"],"tools":["t"]}]}`)); err == nil {
		t.Error("oversized selector accepted")
	}
	if _, err := Parse([]byte(`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":[` + strings.Join(big, ",") + `]}]}`)); err == nil {
		t.Error("oversized tools accepted")
	}
	var rules []string
	for i := 0; i <= MaxRules; i++ {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"]}`, i))
	}
	if _, err := Parse([]byte(`{"version":1,"rules":[` + strings.Join(rules, ",") + `]}`)); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many rules: %v", err)
	}
	if _, err := Parse(make([]byte, MaxBytes+1)); err == nil {
		t.Error("oversized policy accepted")
	}
	p, err := Parse([]byte(`{"version":1,"rules":[]}`))
	if err != nil || p.Evaluate(Subject{AgentID: "a"}, "u", "t", nil).Allowed {
		t.Fatal("empty policy must deny everything")
	}
}

type refRule struct {
	id       string
	deny     bool
	agents   []string
	scopes   []string
	ups      []string
	tools    []string
	maxN     int    // -1: no constraint on n
	prefix   string // "": no constraint on p
	approval bool
}

func (r refRule) json() map[string]any {
	m := map[string]any{"id": r.id, "effect": map[bool]string{true: "deny", false: "allow"}[r.deny],
		"upstreams": r.ups, "tools": r.tools}
	if len(r.agents) > 0 {
		m["agents"] = r.agents
	}
	if len(r.scopes) > 0 {
		m["scopes"] = r.scopes
	}
	props := map[string]any{}
	if r.maxN >= 0 {
		props["n"] = map[string]any{"type": "integer", "maximum": r.maxN}
	}
	if r.prefix != "" {
		if r.deny {
			// Deny rules cannot use allow-list keywords; a pattern says "under this prefix".
			props["p"] = map[string]any{"type": "string", "pattern": "^" + regexp.QuoteMeta(r.prefix) + "(/|$)"}
		} else {
			props["p"] = map[string]any{"type": "string", "x-path-prefix": []string{r.prefix}}
		}
	}
	if len(props) > 0 {
		m["arguments"] = map[string]any{"type": "object", "properties": props}
	}
	if r.approval {
		m["requires_approval"] = true
	}
	return m
}

func refSubject(r refRule, agent string, scopes []string) bool {
	if slices.Contains(r.agents, "*") || slices.Contains(r.agents, agent) {
		return true
	}
	for _, s := range scopes {
		if slices.Contains(r.scopes, s) {
			return true
		}
	}
	return false
}

func refTarget(r refRule, up, tool string) bool {
	if !slices.Contains(r.ups, "*") && !slices.Contains(r.ups, up) {
		return false
	}
	for _, t := range r.tools {
		if t == "*" || t == tool || strings.HasSuffix(t, "*") && strings.HasPrefix(tool, t[:len(t)-1]) {
			return true
		}
	}
	return false
}

func refArgs(r refRule, n int, p string) bool {
	if r.maxN >= 0 && n > r.maxN {
		return false
	}
	under := p == r.prefix || strings.HasPrefix(p, r.prefix+"/")
	if r.prefix != "" && r.deny && !under {
		return false // the deny pattern is purely textual
	}
	if r.prefix != "" && !r.deny && (strings.Contains(p, "..") || !under) {
		return false // the allow-list also refuses non-canonical paths
	}
	return true
}

// refEvaluate is a deliberately naive restatement of the rules in the package
// comment, written without the engine's index or schema package.
func refEvaluate(rules []refRule, agent string, scopes []string, up, tool string, n int, p string) (bool, string, string, bool) {
	for _, r := range rules {
		if r.deny && refSubject(r, agent, scopes) && refTarget(r, up, tool) && refArgs(r, n, p) {
			return false, r.id, "", false
		}
	}
	constraint := ""
	for _, r := range rules {
		if r.deny || !refSubject(r, agent, scopes) || !refTarget(r, up, tool) {
			continue
		}
		if refArgs(r, n, p) {
			return true, r.id, "", r.approval
		}
		if constraint == "" {
			constraint = r.id
		}
	}
	return false, DefaultDenyID, constraint, false
}

func refVisible(rules []refRule, agent string, scopes []string, up, tool string) bool {
	allow := false
	for _, r := range rules {
		if !refSubject(r, agent, scopes) || !refTarget(r, up, tool) {
			continue
		}
		if r.deny && r.maxN < 0 && r.prefix == "" {
			return false
		}
		allow = allow || !r.deny
	}
	return allow
}

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.IntN(len(xs))] }

func subset(rng *rand.Rand, xs []string) []string {
	var out []string
	for _, x := range xs {
		if rng.IntN(3) == 0 {
			out = append(out, x)
		}
	}
	return out
}

func randomRule(rng *rand.Rand, i int) refRule {
	r := refRule{id: fmt.Sprintf("r%d", i), deny: rng.IntN(4) == 0, maxN: -1}
	if rng.IntN(5) == 0 {
		r.agents = []string{"*"}
	} else {
		r.agents = subset(rng, []string{"alice", "bob", "carol"})
		r.scopes = subset(rng, []string{"read", "write"})
		if len(r.agents)+len(r.scopes) == 0 {
			r.agents = []string{pick(rng, []string{"alice", "bob", "carol"})}
		}
	}
	if rng.IntN(4) == 0 {
		r.ups = []string{"*"}
	} else if r.ups = subset(rng, []string{"fs", "web"}); len(r.ups) == 0 {
		r.ups = []string{"fs"}
	}
	if rng.IntN(6) == 0 {
		r.tools = []string{"*"}
	} else if r.tools = subset(rng, []string{"read_file", "write_file", "http_get", "read_*"}); len(r.tools) == 0 {
		r.tools = []string{"read_file"}
	}
	if rng.IntN(3) == 0 {
		r.maxN = rng.IntN(10)
	}
	if rng.IntN(3) == 0 {
		r.prefix = pick(rng, []string{"/a", "/b", "/a/x"})
	}
	r.approval = !r.deny && rng.IntN(5) == 0
	return r
}

func TestRandomPoliciesMatchReference(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(seed, 7))
	paths := []string{"/a", "/a/x", "/a/x/y", "/b/q", "/ab", "../a/x", "/a/../b/q", "/c"}
	for iter := 0; iter < 400; iter++ {
		var rules []refRule
		var js []any
		for i := range rng.IntN(12) {
			r := randomRule(rng, i)
			rules = append(rules, r)
			js = append(js, r.json())
		}
		if js == nil {
			js = []any{}
		}
		src, _ := json.Marshal(map[string]any{"version": 1, "rules": js})
		p, err := Parse(src)
		if err != nil {
			t.Fatalf("seed %d: generated policy rejected: %v\n%s", seed, err, src)
		}
		for range 100 {
			agent := pick(rng, []string{"alice", "bob", "carol", "dave"})
			scopes := subset(rng, []string{"read", "write"})
			up := pick(rng, []string{"fs", "web", "db"})
			tool := pick(rng, []string{"read_file", "write_file", "http_get", "read_dir", "exec"})
			n := rng.IntN(12)
			pth := pick(rng, paths)
			a := args(t, fmt.Sprintf(`{"n":%d,"p":%q}`, n, pth))
			d := p.Evaluate(Subject{AgentID: agent, Scopes: scopes}, up, tool, a)
			ok, id, constraint, approval := refEvaluate(rules, agent, scopes, up, tool, n, pth)
			if d.Allowed != ok || d.RuleID != id || d.ConstraintRuleID != constraint || d.RequiresApproval != approval {
				t.Fatalf("seed %d: %s %v %s.%s n=%d p=%s\nengine:    %+v\nreference: allowed=%v rule=%s constraint=%s approval=%v\npolicy: %s",
					seed, agent, scopes, up, tool, n, pth, d, ok, id, constraint, approval, src)
			}
			if got, want := p.Visible(Subject{AgentID: agent, Scopes: scopes}, up, tool), refVisible(rules, agent, scopes, up, tool); got != want {
				t.Fatalf("seed %d: Visible(%s %v %s.%s) = %v, reference %v\npolicy: %s", seed, agent, scopes, up, tool, got, want, src)
			}
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoreReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	v1 := `{"version":1,"rules":[]}`
	v2 := `{"version":1,"rules":[{"id":"a","effect":"allow","agents":["*"],"upstreams":["*"],"tools":["*"]}]}`
	writeFile(t, path, v1)
	var mu sync.Mutex
	var events []ReloadResult
	s, err := OpenStore(path, func(r ReloadResult) { mu.Lock(); events = append(events, r); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	h1 := s.Current().Hash
	if r := s.Reload(); r.Changed || r.Err != nil || r.Hash != h1 {
		t.Fatalf("no-op reload: %+v", r)
	}
	writeFile(t, path, v2)
	r := s.Reload()
	if !r.Changed || r.PrevHash != h1 || r.Hash == h1 || s.Current().Hash != r.Hash {
		t.Fatalf("reload: %+v", r)
	}
	writeFile(t, path, `{"version":1,"rules":[{"id":"x"`) // torn write
	if r := s.Reload(); r.Err == nil || r.Changed || s.Current().Hash != r.PrevHash {
		t.Fatalf("invalid file must keep the old policy: %+v", r)
	}
	if !s.Current().Evaluate(Subject{AgentID: "z"}, "u", "t", nil).Allowed {
		t.Fatal("old policy not in force")
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 reload events, got %d", n)
	}
	if _, err := OpenStore(filepath.Join(dir, "missing.json"), nil); err == nil {
		t.Fatal("missing file opened")
	}
	writeFile(t, filepath.Join(dir, "bad.json"), `{}`)
	if _, err := OpenStore(filepath.Join(dir, "bad.json"), nil); err == nil {
		t.Fatal("invalid file opened")
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(filepath.Join(dir, "d"), nil); err == nil {
		t.Fatal("directory opened")
	}
}

// writeAtomic replaces a file the way deployments should: write a temporary
// file, then rename it over the old one, so a reader never sees half of it.
func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	writeFile(t, tmp, content)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestStoreWatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeFile(t, path, `{"version":1,"rules":[]}`)
	results := make(chan ReloadResult, 10)
	s, err := OpenStore(path, func(r ReloadResult) { results <- r })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, 5*time.Millisecond); close(done) }()
	next := func() ReloadResult {
		select {
		case r := <-results:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("no reload observed")
			return ReloadResult{}
		}
	}
	writeAtomic(t, path, `{"version":1,"rules":[{"id":"a","effect":"allow","agents":["*"],"upstreams":["*"],"tools":["*"]}]}`)
	if r := next(); !r.Changed {
		t.Fatalf("watch: %+v", r)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if r := next(); r.Err == nil {
		t.Fatalf("missing file: %+v", r)
	}
	time.Sleep(30 * time.Millisecond) // a missing file is reported once
	select {
	case r := <-results:
		t.Fatalf("repeated report: %+v", r)
	default:
	}
	writeAtomic(t, path, `{"version":1,"rules":[]}`)
	if r := next(); !r.Changed {
		t.Fatalf("recreated: %+v", r)
	}
	// A same-size rewrite is still noticed: contents are compared, not mtimes.
	writeAtomic(t, path, `{"version":1,"rules":[]} `)
	writeAtomic(t, path, `{"version":1,"rules":[{"id":"b","effect":"deny","agents":["*"],"upstreams":["*"],"tools":["*"]}]}`)
	if r := next(); !r.Changed {
		t.Fatalf("rewrite: %+v", r)
	}
	writeAtomic(t, path, `{"version":1,"rules":[{"id":"c","effect":"deny","agents":["*"],"upstreams":["*"],"tools":["*"]}]}`)
	if r := next(); !r.Changed {
		t.Fatalf("same-size rewrite: %+v", r)
	}
	cancel()
	<-done
}

func BenchmarkEvaluate(b *testing.B) {
	var rules []string
	for i := range 200 {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","effect":"allow","agents":["agent-%d"],"upstreams":["up%d"],"tools":["tool_%d"]}`, i, i, i%10, i))
	}
	rules = append(rules, `{"id":"fs-read","effect":"allow","scopes":["files:read"],"upstreams":["fs"],"tools":["read_file"],
	  "arguments":{"type":"object","required":["path"],"properties":{"path":{"type":"string","x-path-prefix":["/sandbox"]}}}}`)
	p, err := Parse([]byte(`{"version":1,"rules":[` + strings.Join(rules, ",") + `]}`))
	if err != nil {
		b.Fatal(err)
	}
	s := Subject{AgentID: "alice", Scopes: []string{"files:read"}}
	a := args(b, `{"path":"/sandbox/reports/q1.csv"}`)
	for b.Loop() {
		if !p.Evaluate(s, "fs", "read_file", a).Allowed {
			b.Fatal("denied")
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(example))
	f.Add([]byte(`{"version":1,"rules":[]}`))
	f.Add([]byte(`{"version":1,"rules":[{"id":"r","effect":"deny","scopes":["s"],"upstreams":["*"],"tools":["a*"]}]}`))
	f.Fuzz(func(t *testing.T, src []byte) {
		p, err := Parse(src)
		if err != nil {
			return
		}
		q, err := Parse(src)
		if err != nil || q.Hash != p.Hash || len(q.Rules) != len(p.Rules) {
			t.Fatal("parse is not deterministic")
		}
		s := Subject{AgentID: "a", Scopes: []string{"s"}}
		for _, up := range []string{"u", "fs", "x"} {
			d := p.Evaluate(s, up, "tool", map[string]any{"path": "/x"})
			if d.RuleID == "" || d.Allowed && d.RuleID == DefaultDenyID {
				t.Fatalf("bad decision %+v", d)
			}
			p.Visible(s, up, "tool")
		}
	})
}
