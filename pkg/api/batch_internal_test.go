package api

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
)

// A batch loads each module's files with one call per side, and sends only
// the files that call cannot cover to the single-file loader: an
// ill-typed package (here sorting first, so a whole-group build would
// fail), a file the default build excludes, and a file outside any module.
func TestDiffBatch_LoadsEachModuleOnce(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"m/go.mod":      "module example.com/m\n\ngo 1.22\n",
		"m/a/bad.go":    "package a\n\nfunc A() int { return undefinedThing }\n",
		"m/p/one.go":    "package p\n\nfunc One() int { return 1 }\n",
		"m/p/two.go":    "package p\n\nfunc Two() int { return 2 }\n",
		"m/p/x_test.go": "package p\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		"m/q/q.go":      "package q\n\nfunc Q() int { return 3 }\n",
		"loose/main.go": "package main\n\nfunc main() {}\n",
	}
	for name, src := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := func(name string) string { return filepath.Join(root, name) }

	var groupLoads [][]string
	var singles []string
	origLoad, origSingle := loadFiles, fingerprintSource
	t.Cleanup(func() { loadFiles, fingerprintSource = origLoad, origSingle })
	loadFiles = func(dir string, overlay map[string][]byte) ([]*packages.Package, error) {
		var names []string
		for f := range overlay {
			rel, _ := filepath.Rel(root, f)
			names = append(names, rel)
		}
		sort.Strings(names)
		groupLoads = append(groupLoads, names)
		return origLoad(dir, overlay)
	}
	fingerprintSource = func(f, src string, policy ir.LiteralPolicy) ([]diff.FingerprintResult, error) {
		rel, _ := filepath.Rel(root, f)
		singles = append(singles, rel)
		return origSingle(f, src, policy)
	}

	var pairs []DiffPair
	for _, name := range []string{"m/a/bad.go", "m/p/one.go", "m/p/two.go", "m/p/x_test.go", "m/q/q.go", "loose/main.go"} {
		pairs = append(pairs, DiffPair{Old: path(name), New: path(name)})
	}
	out := DiffBatch(pairs)

	wantGroup := []string{"m/a/bad.go", "m/p/one.go", "m/p/two.go", "m/p/x_test.go", "m/q/q.go"}
	if len(groupLoads) != 2 {
		t.Fatalf("group loads = %v; want one per side", groupLoads)
	}
	for _, g := range groupLoads {
		if len(g) != len(wantGroup) {
			t.Fatalf("group load of %v; want %v", g, wantGroup)
		}
		for i := range g {
			if g[i] != wantGroup[i] {
				t.Fatalf("group load of %v; want %v", g, wantGroup)
			}
		}
	}
	sort.Strings(singles)
	wantSingles := []string{"loose/main.go", "loose/main.go", "m/a/bad.go", "m/a/bad.go", "m/p/x_test.go", "m/p/x_test.go"}
	if len(singles) != len(wantSingles) {
		t.Fatalf("single-file loads = %v; want %v", singles, wantSingles)
	}
	for i := range singles {
		if singles[i] != wantSingles[i] {
			t.Fatalf("single-file loads = %v; want %v", singles, wantSingles)
		}
	}
	if out[0].ErrorMessage == "" {
		t.Errorf("ill-typed a/bad.go: no error")
	}
	for i := 1; i < len(out); i++ {
		if out[i].ErrorMessage != "" || len(out[i].Functions) == 0 {
			t.Errorf("pair %d (%s): error %q, %d functions; want a clean diff", i, filepath.Base(pairs[i].New), out[i].ErrorMessage, len(out[i].Functions))
		}
	}
}
