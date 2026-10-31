//go:build ignore

// rewrite-imports changes import paths in Go files and nothing else. It is
// how trees move into this module: git mv the directory, then rewrite the
// imports that pointed at the old location.
//
//	go run scripts/rewrite-imports.go \
//	    -map github.com/laiwf94/wicket/internal=github.com/laiwf94/authz/internal/authn \
//	    internal/authn cmd examples
//
// Only import specs change; each file is checked to be byte-identical to the
// original with its import declarations removed, and if any file fails that
// check nothing is written. -n reports what would change without writing.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/laiwf94/authz/internal/importrewrite"
)

type mapsFlag []importrewrite.Mapping

func (m *mapsFlag) String() string {
	parts := make([]string, len(*m))
	for i, mp := range *m {
		parts[i] = mp.From + "=" + mp.To
	}
	return strings.Join(parts, ", ")
}

func (m *mapsFlag) Set(s string) error {
	mp, err := importrewrite.ParseMapping(s)
	if err != nil {
		return err
	}
	*m = append(*m, mp)
	return nil
}

func main() {
	var maps mapsFlag
	dry := flag.Bool("n", false, "report the changes without writing them")
	flag.Var(&maps, "map", "old=new import path prefix (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/rewrite-imports.go [-n] -map old=new [-map ...] dir...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(maps) == 0 || flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	r, err := importrewrite.New(maps...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rewrite-imports:", err)
		os.Exit(2)
	}
	changes, err := r.Tree(flag.Args(), *dry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rewrite-imports:", err)
		os.Exit(1)
	}
	specs := 0
	for _, c := range changes {
		fmt.Printf("%s: %d import(s)\n", c.Path, c.Specs)
		specs += c.Specs
	}
	verb := "rewrote"
	if *dry {
		verb = "would rewrite"
	}
	fmt.Fprintf(os.Stderr, "%s %d import(s) in %d file(s) [%s]\n", verb, specs, len(changes), maps.String())
}
