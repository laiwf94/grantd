package importrewrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustNew(t *testing.T, specs ...string) *Rewriter {
	t.Helper()
	var maps []Mapping
	for _, s := range specs {
		m, err := ParseMapping(s)
		if err != nil {
			t.Fatal(err)
		}
		maps = append(maps, m)
	}
	r, err := New(maps...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseMapping(t *testing.T) {
	for _, bad := range []string{"", "a", "=b", "a=", "a/=b", "a=b/"} {
		if _, err := ParseMapping(bad); err == nil {
			t.Errorf("ParseMapping(%q) accepted", bad)
		}
	}
	m, err := ParseMapping(" x/y = z/w ")
	if err != nil || m.From != "x/y" || m.To != "z/w" {
		t.Fatalf("got %+v, %v", m, err)
	}
}

func TestNewRejects(t *testing.T) {
	if _, err := New(); err == nil {
		t.Error("no mappings accepted")
	}
	if _, err := New(Mapping{"a", "b"}, Mapping{"a", "c"}); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := New(Mapping{"", "b"}); err == nil {
		t.Error("empty accepted")
	}
}

func TestPath(t *testing.T) {
	r := mustNew(t, "ex.com/w/internal=ex.com/a/internal/authn", "ex.com/w/internal/metrics=ex.com/a/internal/authn/wmetrics")
	cases := map[string]string{
		"ex.com/w/internal":           "ex.com/a/internal/authn",
		"ex.com/w/internal/jose":      "ex.com/a/internal/authn/jose",
		"ex.com/w/internal/jose/sub":  "ex.com/a/internal/authn/jose/sub",
		"ex.com/w/internal/metrics":   "ex.com/a/internal/authn/wmetrics", // longest wins
		"ex.com/w/internalx":          "ex.com/w/internalx",               // not a path prefix
		"ex.com/w":                    "ex.com/w",
		"net/http":                    "net/http",
		"ex.com/w/internal/metrics/x": "ex.com/a/internal/authn/wmetrics/x",
	}
	for in, want := range cases {
		if got, _ := r.Path(in); got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
	}
}

const before = `// Package p is a test.
package p

import (
	"fmt"
	"net/http"

	"github.com/aaa/zeta"
	"github.com/old/mod/internal/jose"
	seal "github.com/old/mod/internal/seal"
)

import _ "github.com/old/mod/internal/side"

// The literal "github.com/old/mod/internal/jose" in code must survive.
const s = "github.com/old/mod/internal/jose"

func F() { fmt.Println(http.MethodGet, jose.X, seal.Y, zeta.Z, s) }
`

func TestSourceRewritesOnlyImports(t *testing.T) {
	r := mustNew(t, "github.com/old/mod/internal=github.com/new/mod/internal/authn")
	out, n, err := r.Source("p.go", []byte(before))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("changed %d specs, want 3", n)
	}
	got := string(out)
	for _, want := range []string{
		`"github.com/new/mod/internal/authn/jose"`,
		`seal "github.com/new/mod/internal/authn/seal"`,
		`import _ "github.com/new/mod/internal/authn/side"`,
		`const s = "github.com/old/mod/internal/jose"`,
		`// The literal "github.com/old/mod/internal/jose" in code must survive.`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %s:\n%s", want, got)
		}
	}
	a, _ := StripImports("p.go", []byte(before))
	b, _ := StripImports("p.go", out)
	if string(a) != string(b) {
		t.Errorf("non-import code changed:\n%s\n---\n%s", a, b)
	}
	// Idempotent: a second pass changes nothing.
	again, n2, err := r.Source("p.go", out)
	if err != nil || n2 != 0 || string(again) != got {
		t.Fatalf("second pass: n=%d err=%v", n2, err)
	}
}

func TestSourceKeepsGofmtOrder(t *testing.T) {
	// Renaming moves jose ahead of zeta's sort position; gofmt order must hold.
	r := mustNew(t, "github.com/old/mod/internal=github.com/a/internal")
	out, _, err := r.Source("p.go", []byte(before))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(out), `"github.com/a/internal/jose"`)
	j := strings.Index(string(out), `"github.com/aaa/zeta"`)
	if i < 0 || j < 0 || i > j {
		t.Fatalf("imports not sorted:\n%s", out)
	}
}

func TestSourceUnchangedAndErrors(t *testing.T) {
	r := mustNew(t, "x/y=z/w")
	out, n, err := r.Source("p.go", []byte(before))
	if err != nil || n != 0 || string(out) != before {
		t.Fatalf("untouched file changed: n=%d err=%v", n, err)
	}
	if _, _, err := r.Source("bad.go", []byte("package")); err == nil {
		t.Error("unparsable file accepted")
	}
	// A file that is not gofmt-clean would be reformatted outside the
	// import block, so the rewrite must refuse it.
	ugly := "package p\n\nimport \"x/y/q\"\n\nfunc  F( ) { q.Z() }\n"
	if _, _, err := r.Source("ugly.go", []byte(ugly)); err == nil || !strings.Contains(err.Error(), "outside the import block") {
		t.Errorf("non-gofmt file: err = %v", err)
	}
}

func TestTree(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a/a.go", "package a\n\nimport \"x/y/q\"\n\nvar _ = q.Z\n")
	b := write("a/b_test.go", "package a\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n")
	td := write("a/testdata/t.go", "package t\n\nimport \"x/y/q\"\n")
	hid := write(".git/h.go", "package h\n\nimport \"x/y/q\"\n")
	txt := write("a/notes.txt", "import \"x/y/q\"\n")
	r := mustNew(t, "x/y=z/w")

	ch, err := r.Tree([]string{dir}, true)
	if err != nil || len(ch) != 1 || ch[0].Path != a || ch[0].Specs != 1 {
		t.Fatalf("dry run: %+v, %v", ch, err)
	}
	if data, _ := os.ReadFile(a); !strings.Contains(string(data), `"x/y/q"`) {
		t.Fatal("dry run wrote")
	}
	if _, err := r.Tree([]string{dir}, false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(a); !strings.Contains(string(data), `"z/w/q"`) {
		t.Fatalf("not rewritten: %s", data)
	}
	for _, p := range []string{td, hid, txt} {
		if data, _ := os.ReadFile(p); !strings.Contains(string(data), `"x/y/q"`) {
			t.Errorf("%s should be skipped", p)
		}
	}
	if data, _ := os.ReadFile(b); !strings.Contains(string(data), `"fmt"`) {
		t.Error("unrelated file changed")
	}

	// One bad file anywhere means nothing is written.
	c := write("c/c.go", "package c\n\nimport \"z/w/q\"\n\nvar _ = q.Z\n")
	write("d/d.go", "package")
	back := mustNew(t, "z/w=x/y")
	if _, err := back.Tree([]string{dir}, false); err == nil {
		t.Fatal("broken file accepted")
	}
	if data, _ := os.ReadFile(c); !strings.Contains(string(data), `"z/w/q"`) {
		t.Error("partial write after a refused file")
	}
	if _, err := r.Tree([]string{filepath.Join(dir, "missing")}, true); err == nil {
		t.Error("missing root accepted")
	}
}
