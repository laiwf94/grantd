// Package importrewrite changes import paths in Go source files and nothing
// else. It backs scripts/rewrite-imports.go, which the module merge uses to
// move packages without touching a single line of code or test bodies.
//
// Only the string literal of each import spec is replaced. The file is then
// passed through go/format so that gofmt's import sorting stays satisfied,
// and the result is checked: with every import declaration removed, the old
// and new files must be byte-identical. A file that would change anywhere
// else is refused rather than written.
package importrewrite

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Mapping replaces the import path From, and every path below it, with To.
type Mapping struct {
	From, To string
}

// ParseMapping reads "old=new".
func ParseMapping(s string) (Mapping, error) {
	from, to, ok := strings.Cut(s, "=")
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if !ok || from == "" || to == "" {
		return Mapping{}, fmt.Errorf("mapping %q: want old/import/path=new/import/path", s)
	}
	if strings.HasSuffix(from, "/") || strings.HasSuffix(to, "/") {
		return Mapping{}, fmt.Errorf("mapping %q: paths must not end in /", s)
	}
	return Mapping{From: from, To: to}, nil
}

// Rewriter applies a set of mappings. When several mappings match a path the
// longest From wins, so a specific package can be routed apart from its tree.
type Rewriter struct {
	maps []Mapping
}

// New returns a Rewriter for the mappings. Duplicate From paths are an error.
func New(maps ...Mapping) (*Rewriter, error) {
	if len(maps) == 0 {
		return nil, errors.New("no mappings")
	}
	seen := map[string]bool{}
	sorted := append([]Mapping(nil), maps...)
	for _, m := range sorted {
		if m.From == "" || m.To == "" {
			return nil, errors.New("empty mapping path")
		}
		if seen[m.From] {
			return nil, fmt.Errorf("duplicate mapping for %s", m.From)
		}
		seen[m.From] = true
	}
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].From) > len(sorted[j].From) })
	return &Rewriter{maps: sorted}, nil
}

// Path returns the rewritten import path and whether a mapping applied.
func (r *Rewriter) Path(p string) (string, bool) {
	for _, m := range r.maps {
		if p == m.From {
			return m.To, true
		}
		if strings.HasPrefix(p, m.From+"/") {
			return m.To + p[len(m.From):], true
		}
	}
	return p, false
}

// Source rewrites one file's contents. It returns the new contents, the
// number of import specs changed, and an error if the file does not parse or
// the rewrite would touch anything outside its import declarations.
func (r *Rewriter) Source(filename string, src []byte) ([]byte, int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return nil, 0, err
	}
	type edit struct {
		start, end int
		lit        string
	}
	var edits []edit
	for _, spec := range f.Imports {
		old, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: bad import %s", fset.Position(spec.Pos()), spec.Path.Value)
		}
		np, ok := r.Path(old)
		if !ok || np == old {
			continue
		}
		edits = append(edits, edit{
			start: fset.Position(spec.Path.Pos()).Offset,
			end:   fset.Position(spec.Path.End()).Offset,
			lit:   strconv.Quote(np),
		})
	}
	if len(edits) == 0 {
		return src, 0, nil
	}
	var out bytes.Buffer
	last := 0
	for _, e := range edits { // f.Imports is in source order
		out.Write(src[last:e.start])
		out.WriteString(e.lit)
		last = e.end
	}
	out.Write(src[last:])
	formatted, err := format.Source(out.Bytes())
	if err != nil {
		return nil, 0, fmt.Errorf("%s: format after rewrite: %w", filename, err)
	}
	before, err := StripImports(filename, src)
	if err != nil {
		return nil, 0, err
	}
	after, err := StripImports(filename, formatted)
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(before, after) {
		return nil, 0, fmt.Errorf("%s: rewrite would change code outside the import block (is the file gofmt-clean?)", filename)
	}
	return formatted, len(edits), nil
}

// StripImports returns src with every import declaration removed. Two files
// whose stripped forms are equal differ only in their imports.
func StripImports(filename string, src []byte) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	last := 0
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		start := fset.Position(gd.Pos()).Offset
		if gd.Doc != nil {
			start = fset.Position(gd.Doc.Pos()).Offset
		}
		out.Write(src[last:start])
		last = fset.Position(gd.End()).Offset
	}
	out.Write(src[last:])
	return out.Bytes(), nil
}

// Change records one rewritten file.
type Change struct {
	Path  string
	Specs int
}

// Tree rewrites every .go file under the roots, skipping vendor, testdata and
// hidden directories. With dryRun set nothing is written. Every file is
// checked before any is written, so a refused file leaves the tree untouched.
func (r *Rewriter) Tree(roots []string, dryRun bool) ([]Change, error) {
	type pending struct {
		path string
		mode os.FileMode
		data []byte
		n    int
	}
	var todo []pending
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if p != root && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			data, n, err := r.Source(p, src)
			if err != nil {
				return err
			}
			if n > 0 {
				info, err := d.Info()
				if err != nil {
					return err
				}
				todo = append(todo, pending{p, info.Mode().Perm(), data, n})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	changes := make([]Change, 0, len(todo))
	for _, t := range todo {
		if !dryRun {
			if err := os.WriteFile(t.path, t.data, t.mode); err != nil {
				return changes, err
			}
		}
		changes = append(changes, Change{Path: t.path, Specs: t.n})
	}
	return changes, nil
}
