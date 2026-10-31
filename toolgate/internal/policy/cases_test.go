package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCases(t testing.TB, src string) *Cases {
	t.Helper()
	cs, err := ParseCases([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func casesDoc(cases ...string) string {
	return `{"version":1,"cases":[` + strings.Join(cases, ",") + `]}`
}

const aliceSubj = `"subject":{"agent":"alice-bot","scopes":["files:read"]}`

func TestParseCasesErrors(t *testing.T) {
	call := func(expect string) string {
		return `{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.read_file"},"expect":` + expect + `}`
	}
	list := func(expect string) string {
		return `{"name":"c",` + aliceSubj + `,"list":["fs.read_file","fs.list_dir"],"expect":` + expect + `}`
	}
	cases := []struct{ src, want string }{
		{`{"version":2,"cases":[]}`, "version must be 1"},
		{`{"version":1,"cases":[]}`, "no cases"},
		{`{"version":1}`, "no cases"},
		{`{"version":1,"cases":[],"extra":1}`, "unknown field"},
		{`{"version":1,"version":1,"cases":[]}`, "duplicate"},
		{`[1]`, "cannot unmarshal"},
		{casesDoc(call(`{"decision":"allow"}`), call(`{"decision":"deny"}`)), "used twice"},
		{casesDoc(strings.Replace(call(`{"decision":"allow"}`), `"name":"c"`, `"name":""`, 1)), "name must be"},
		{casesDoc(strings.Replace(call(`{"decision":"allow"}`), `"name":"c"`, `"name":"a\nb"`, 1)), "name must be"},
		{casesDoc(`{"name":"c","subject":{"agent":""},"call":{"tool":"fs.x"},"expect":{"decision":"allow"}}`), "not a valid agent id"},
		{casesDoc(`{"name":"c","subject":{"agent":"a","scopes":["bad scope"]},"call":{"tool":"fs.x"},"expect":{"decision":"allow"}}`), "scope"},
		{casesDoc(`{"name":"c","subject":{"agent":"a","role":"x"},"call":{"tool":"fs.x"},"expect":{"decision":"allow"}}`), "unknown field"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"expect":{"decision":"allow"}}`), `needs "call" or "list"`},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.x"},"list":["fs.x"],"expect":{"decision":"allow"}}`), "not both"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"read_file"},"expect":{"decision":"allow"}}`), "upstream.tool"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"FS.read_file"},"expect":{"decision":"allow"}}`), "upstream.tool"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.read file"},"expect":{"decision":"allow"}}`), "upstream.tool"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.x","arguments":[1]},"expect":{"decision":"allow"}}`), "must be an object"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.x","arguments":{"a":1,"a":2}},"expect":{"decision":"allow"}}`), "duplicate"},
		{casesDoc(call(`{}`)), "decision must be"},
		{casesDoc(call(`{"decision":"Allow"}`)), "decision must be"},
		{casesDoc(call(`{"decision":"allow","rul":"x"}`)), "unknown field"},
		{casesDoc(call(`{"decision":"allow","rule":"bad id!"}`)), "not a valid rule id"},
		{casesDoc(call(`{"decision":"allow","rule":"default-deny"}`)), `cannot expect rule "default-deny"`},
		{casesDoc(call(`{"decision":"allow","constraint_rule":"fs-read"}`)), "only to denials"},
		{casesDoc(call(`{"decision":"allow","hidden":false}`)), "only to denials"},
		{casesDoc(call(`{"decision":"deny","requires_approval":false}`)), "only to allowed calls"},
		{casesDoc(call(`{"decision":"allow","visible":[]}`)), "only to list cases"},
		{casesDoc(list(`{"decision":"allow","visible":[]}`)), "expects only visible"},
		{casesDoc(list(`{}`)), `must expect "visible"`},
		{casesDoc(list(`{"visible":["fs.other"]}`)), "does not offer"},
		{casesDoc(list(`{"visible":["fs.list_dir","fs.list_dir"]}`)), "twice"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"list":[],"expect":{"visible":[]}}`), "list must name"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"list":["fs.a","fs.a"],"expect":{"visible":[]}}`), "twice"},
		{casesDoc(`{"name":"c",` + aliceSubj + `,"list":["a"],"expect":{"visible":[]}}`), "upstream.tool"},
	}
	for _, c := range cases {
		_, err := ParseCases([]byte(c.src))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseCases(%s)\n  error %v, want it to mention %q", c.src, err, c.want)
		}
	}
	if _, err := ParseCases(bytes.Repeat([]byte(" "), MaxCaseBytes+1)); err == nil {
		t.Error("oversized case file accepted")
	}
	many := make([]string, MaxCases+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"name":"c%d","subject":{"agent":"a"},"call":{"tool":"u.t"},"expect":{"decision":"deny"}}`, i)
	}
	if _, err := ParseCases([]byte(casesDoc(many...))); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many cases: %v", err)
	}
}

func TestRunCases(t *testing.T) {
	p, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	cs := mustCases(t, casesDoc(
		`{"name":"read in sandbox",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/sandbox/a.txt"}},
		  "expect":{"decision":"allow","rule":"fs-read","requires_approval":false,"reason_contains":"fs-read"}}`,
		`{"name":"read outside",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/etc/passwd"}},
		  "expect":{"decision":"deny","rule":"default-deny","constraint_rule":"fs-read","hidden":false,"reason_contains":"outside"}}`,
		`{"name":"no secrets",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/sandbox/.env"}},
		  "expect":{"decision":"deny","rule":"no-secrets"}}`,
		`{"name":"deploy needs approval","subject":{"agent":"alice-bot"},"call":{"tool":"ops.deploy"},
		  "expect":{"decision":"allow","rule":"deploy","requires_approval":true}}`,
		`{"name":"bob is hidden","subject":{"agent":"bob-bot"},"call":{"tool":"fs.read_file","arguments":{"path":"/sandbox/a"}},
		  "expect":{"decision":"deny","rule":"default-deny","hidden":true}}`,
		`{"name":"admin tools denied for root too","subject":{"agent":"root-bot"},"call":{"tool":"web.admin_reset"},
		  "expect":{"decision":"deny","rule":"no-admin","hidden":false}}`,
		`{"name":"numbers decode as in the gateway","subject":{"agent":"alice-bot"},"call":{"tool":"web.get","arguments":{"url":"https://api.example.com/","n":1e400}},
		  "expect":{"decision":"allow","rule":"web"}}`,
		`{"name":"alice list",`+aliceSubj+`,"list":["fs.read_file","fs.list_dir","fs.write_file"],
		  "expect":{"visible":["fs.list_dir","fs.read_file"]}}`,
		`{"name":"root list","subject":{"agent":"root-bot"},"list":["web.admin_x","web.get"],"expect":{"visible":["web.get"]}}`,
		`{"name":"bob list","subject":{"agent":"bob-bot"},"list":["fs.read_file"],"expect":{"visible":[]}}`,
	))
	rep := RunCases(p, cs)
	if rep.Failed != 0 || rep.Passed != len(cs.Cases) {
		var b bytes.Buffer
		rep.WriteText(&b, false)
		t.Fatalf("expected every case to pass:\n%s", b.String())
	}

	// Each kind of expectation that does not hold is reported as its own
	// mismatch, with what was wanted and what was decided.
	cs = mustCases(t, casesDoc(
		`{"name":"wrong decision",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/etc/passwd"}},
		  "expect":{"decision":"allow","rule":"fs-read"}}`,
		`{"name":"wrong rule",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/sandbox/.env"}},
		  "expect":{"decision":"deny","rule":"default-deny","constraint_rule":"fs-read"}}`,
		`{"name":"approval",`+aliceSubj+`,"call":{"tool":"ops.deploy"},"expect":{"decision":"allow","requires_approval":false}}`,
		`{"name":"reason",`+aliceSubj+`,"call":{"tool":"fs.read_file","arguments":{"path":"/etc/passwd"}},
		  "expect":{"decision":"deny","reason_contains":"no rule allows"}}`,
		`{"name":"hidden","subject":{"agent":"bob-bot"},"call":{"tool":"fs.read_file"},"expect":{"decision":"deny","hidden":false}}`,
		`{"name":"renamed rule",`+aliceSubj+`,"call":{"tool":"fs.list_dir","arguments":{"path":"/sandbox"}},"expect":{"decision":"allow","rule":"fs-read-old"}}`,
		`{"name":"list",`+aliceSubj+`,"list":["fs.read_file","fs.write_file"],"expect":{"visible":["fs.write_file"]}}`,
	))
	rep = RunCases(p, cs)
	if rep.Passed != 0 || rep.Failed != len(cs.Cases) {
		t.Fatalf("passed %d, failed %d", rep.Passed, rep.Failed)
	}
	want := map[string][]Mismatch{
		"wrong decision": {{"decision", "allow", "deny"}, {"rule", "fs-read", "default-deny"}},
		"wrong rule":     {{"rule", "default-deny", "no-secrets"}, {"constraint_rule", "fs-read", "(none)"}},
		"approval":       {{"requires_approval", "false", "true"}},
		"reason":         {{"reason", `contains "no rule allows"`, `"arguments rejected by rule fs-read: $.path: path is outside the allowed directories"`}},
		"hidden":         {{"hidden", "false", "true"}},
		"renamed rule":   {{"rule", "fs-read-old (defined in the policy)", "no rule with that id"}, {"rule", "fs-read-old", "fs-read"}},
		"list":           {{"visible", "fs.write_file listed", "hidden"}, {"visible", "fs.read_file hidden", "listed"}},
	}
	for _, r := range rep.Results {
		if fmt.Sprint(r.Mismatches) != fmt.Sprint(want[r.Name]) {
			t.Errorf("%s: mismatches %v, want %v", r.Name, r.Mismatches, want[r.Name])
		}
	}

	var b bytes.Buffer
	rep.WriteText(&b, true)
	out := b.String()
	for _, s := range []string{
		"FAIL wrong decision\n     decision: want allow\n                got deny\n     rule:     want fs-read\n                got default-deny\n",
		"     decided: deny by default-deny (arguments rejected by fs-read): arguments rejected by rule fs-read",
		"     decided: allow by deploy, requires approval: allowed by rule deploy\n",
		"     decided: deny by default-deny, tool hidden from the agent: no rule allows this call\n",
		"     decided: visible [fs.read_file]\n",
		"FAIL 7 cases: 0 passed, 7 failed\n",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("report lacks %q:\n%s", s, out)
		}
	}
}

func TestReportText(t *testing.T) {
	p, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	cs := mustCases(t, casesDoc(
		`{"name":"a","subject":{"agent":"root-bot"},"call":{"tool":"x.y"},"expect":{"decision":"allow"}}`,
		`{"name":"b","subject":{"agent":"bob-bot"},"call":{"tool":"x.y"},"expect":{"decision":"deny"}}`,
	))
	var quiet, verbose bytes.Buffer
	rep := RunCases(p, cs)
	rep.WriteText(&quiet, false)
	rep.WriteText(&verbose, true)
	if got := quiet.String(); got != "PASS 2 cases: 2 passed, 0 failed\n" {
		t.Errorf("quiet report %q", got)
	}
	if got := verbose.String(); got != "ok   a\nok   b\nPASS 2 cases: 2 passed, 0 failed\n" {
		t.Errorf("verbose report %q", got)
	}
}

// The shipped example cases hold for the shipped example policy. CI also
// runs them through the command.
func TestExampleCases(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p, err := Parse(read("policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ParseCases(read("policy_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rep := RunCases(p, cs); rep.Failed != 0 {
		var b bytes.Buffer
		rep.WriteText(&b, false)
		t.Fatalf("example cases fail:\n%s", b.String())
	}
}

// The runner agrees with Evaluate and Visible on random policies and calls:
// a case written from the engine's own answer passes, and the same case
// with the decision flipped fails on exactly that field.
func TestRunCasesMatchesEngine(t *testing.T) {
	p, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []string{`{"agent":"alice-bot","scopes":["files:read"]}`, `{"agent":"alice-bot"}`, `{"agent":"bob-bot","scopes":["files:read"]}`, `{"agent":"root-bot"}`}
	tools := []string{"fs.read_file", "fs.list_dir", "web.get", "web.admin_x", "ops.deploy", "x.y"}
	argSets := []string{``, `,"arguments":{}`, `,"arguments":{"path":"/sandbox/a"}`, `,"arguments":{"path":"/sandbox/.env"}`, `,"arguments":{"url":"https://api.example.com/"}`, `,"arguments":{"url":"http://10.0.0.1/"}`}
	n := 0
	for _, subj := range subjects {
		for _, tool := range tools {
			for _, a := range argSets {
				n++
				probe := mustCases(t, casesDoc(fmt.Sprintf(`{"name":"p","subject":%s,"call":{"tool":%q%s},"expect":{"decision":"deny"}}`, subj, tool, a)))
				c := probe.Cases[0]
				d := p.Evaluate(c.Subject, c.Call.Upstream, c.Call.Tool, c.Arguments)
				right, wrong := decisionWord(d.Allowed), decisionWord(!d.Allowed)
				good := mustCases(t, casesDoc(fmt.Sprintf(`{"name":"g%d","subject":%s,"call":{"tool":%q%s},"expect":{"decision":%q,"rule":%q}}`, n, subj, tool, a, right, d.RuleID)))
				bad := mustCases(t, casesDoc(fmt.Sprintf(`{"name":"b%d","subject":%s,"call":{"tool":%q%s},"expect":{"decision":%q}}`, n, subj, tool, a, wrong)))
				if rep := RunCases(p, good); rep.Failed != 0 {
					t.Errorf("%s %s%s: case from the engine's own answer fails: %v", subj, tool, a, rep.Results[0].Mismatches)
				}
				if rep := RunCases(p, bad); rep.Failed != 1 || rep.Results[0].Mismatches[0].Field != "decision" {
					t.Errorf("%s %s%s: flipped decision not caught: %+v", subj, tool, a, rep.Results)
				}
			}
		}
	}
}

func FuzzCases(f *testing.F) {
	f.Add([]byte(casesDoc(`{"name":"c",` + aliceSubj + `,"call":{"tool":"fs.read_file","arguments":{"path":"/sandbox/a"}},"expect":{"decision":"allow","rule":"fs-read"}}`)))
	f.Add([]byte(casesDoc(`{"name":"l","subject":{"agent":"bob-bot"},"list":["fs.read_file","web.get"],"expect":{"visible":[]}}`)))
	f.Add([]byte(casesDoc(`{"name":"d","subject":{"agent":"root-bot"},"call":{"tool":"web.admin_x"},"expect":{"decision":"deny","rule":"no-admin","hidden":false,"reason_contains":"forbids"}}`)))
	p, err := Parse([]byte(example))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		cs, err := ParseCases(src)
		if err != nil {
			return
		}
		if len(cs.Cases) == 0 {
			t.Fatal("parsed a file with no cases")
		}
		rep := RunCases(p, cs)
		if rep.Passed+rep.Failed != len(cs.Cases) || len(rep.Results) != len(cs.Cases) {
			t.Fatalf("report counts %d+%d for %d cases", rep.Passed, rep.Failed, len(cs.Cases))
		}
		again := RunCases(p, cs)
		var a, b bytes.Buffer
		rep.WriteText(&a, true)
		again.WriteText(&b, true)
		if a.String() != b.String() {
			t.Fatal("runs are not deterministic")
		}
		for i, c := range cs.Cases {
			if (c.Call == nil) == (c.List == nil) {
				t.Fatalf("case %d is neither or both a call and a list", i)
			}
			if c.Call != nil {
				d := p.Evaluate(c.Subject, c.Call.Upstream, c.Call.Tool, c.Arguments)
				if (d.Allowed != c.Want.Allowed) && rep.Results[i].Passed() {
					t.Fatalf("case %d passed with the wrong decision", i)
				}
			}
		}
	})
}
