package api

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
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

	var mu sync.Mutex
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
		mu.Lock()
		groupLoads = append(groupLoads, names)
		mu.Unlock()
		return origLoad(dir, overlay)
	}
	fingerprintSource = func(f, src string, policy ir.LiteralPolicy, strict bool, keep func(string) bool) ([]diff.FingerprintResult, error) {
		rel, _ := filepath.Rel(root, f)
		mu.Lock()
		singles = append(singles, rel)
		mu.Unlock()
		return origSingle(f, src, policy, strict, keep)
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

// A group whose load fails, or whose fingerprinting panics, sends every
// one of its files to the single-file loader, and the results are those of
// separate diffs.
func TestDiffBatch_GroupFailuresFallBack(t *testing.T) {
	root := t.TempDir()
	for name, src := range map[string]string{
		"m/go.mod":   "module example.com/m\n\ngo 1.22\n",
		"m/p/one.go": "package p\n\nfunc One() int { return 1 }\n",
		"m/q/q.go":   "package q\n\nimport \"os\"\n\nfunc Q(p string) { os.Remove(p) }\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	one, q := filepath.Join(root, "m/p/one.go"), filepath.Join(root, "m/q/q.go")
	pairs := []DiffPair{{Old: one, New: one}, {Old: "", New: q}}
	want := DiffBatch(pairs)
	for i, w := range want {
		if w.ErrorMessage != "" || len(w.Functions) == 0 {
			t.Fatalf("baseline pair %d: error %q, %d functions", i, w.ErrorMessage, len(w.Functions))
		}
	}

	origLoad, origPkgs, origSingle := loadFiles, fingerprintPackages, fingerprintSource
	t.Cleanup(func() { loadFiles, fingerprintPackages, fingerprintSource = origLoad, origPkgs, origSingle })
	for _, c := range []struct {
		name  string
		setup func()
	}{
		{"load error", func() {
			loadFiles = func(string, map[string][]byte) ([]*packages.Package, error) { return nil, os.ErrPermission }
		}},
		{"load error with packages", func() {
			loadFiles = func(root string, overlay map[string][]byte) ([]*packages.Package, error) {
				pkgs, _ := origLoad(root, overlay)
				return pkgs, os.ErrPermission
			}
		}},
		{"fingerprinting panics", func() {
			fingerprintPackages = func([]*packages.Package, ir.LiteralPolicy, bool, func(string) bool) ([]diff.FingerprintResult, error) {
				panic("boom")
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			loadFiles, fingerprintPackages = origLoad, origPkgs
			var mu sync.Mutex
			singles := 0
			fingerprintSource = func(f, src string, policy ir.LiteralPolicy, strict bool, keep func(string) bool) ([]diff.FingerprintResult, error) {
				mu.Lock()
				singles++
				mu.Unlock()
				return origSingle(f, src, policy, strict, keep)
			}
			c.setup()
			got := DiffBatch(pairs)
			if singles != 3 {
				t.Errorf("%d single-file loads; want 3 (one.go on both sides, q.go on the new side)", singles)
			}
			for i := range want {
				if got[i].ErrorMessage != "" || got[i].Summary != want[i].Summary || len(got[i].Functions) != len(want[i].Functions) {
					t.Errorf("pair %d: %+v; want %+v", i, got[i].Summary, want[i].Summary)
				}
			}
		})
	}
}

// A panic while fingerprinting a file on its own fails that file's pair
// only, with the panic in its error.
func TestDiffBatch_SingleFilePanic(t *testing.T) {
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose.go")
	if err := os.WriteFile(loose, []byte("package p\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fingerprintSource
	t.Cleanup(func() { fingerprintSource = orig })
	fingerprintSource = func(string, string, ir.LiteralPolicy, bool, func(string) bool) ([]diff.FingerprintResult, error) {
		panic("boom")
	}
	out := DiffBatch([]DiffPair{{Old: loose, New: loose}, {Old: "", New: ""}})
	if want := "failed to process old file: panic while fingerprinting " + loose + ": boom"; out[0].ErrorMessage != want {
		t.Errorf("error %q; want %q", out[0].ErrorMessage, want)
	}
	if out[1].ErrorMessage != "" {
		t.Errorf("an empty pair failed too: %q", out[1].ErrorMessage)
	}
}

// inFile keeps the functions of the file at path, matched cleaned and
// through symbolic links either way, and the functions without a file.
// Each distinct path is resolved once: a later change to a link does not
// change an answer already given.
func TestInFile_ResolvesEachPathOnce(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	results := []diff.FingerprintResult{
		{FunctionName: "A", Filename: filepath.Join(real, "a.go")},
		{FunctionName: "init"},
		{FunctionName: "B", Filename: filepath.Join(link, "b.go")},
		{FunctionName: "A2", Filename: filepath.Join(link, ".", "a.go")},
	}
	names := func(rs []diff.FingerprintResult) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.FunctionName)
		}
		return strings.Join(out, " ")
	}
	for _, f := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(real, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths := pathResolver{}
	if got := names(inFile(results, filepath.Join(link, "a.go"), paths)); got != "A init A2" {
		t.Errorf("a.go through the link: got %q, want %q", got, "A init A2")
	}
	if got := names(inFile(results, filepath.Join(real, "b.go"), paths)); got != "init B" {
		t.Errorf("b.go: got %q, want %q", got, "init B")
	}

	// Point the link elsewhere: paths answers as before, a new resolver
	// sees the change.
	other := filepath.Join(root, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if got := names(inFile(results, filepath.Join(real, "b.go"), paths)); got != "init B" {
		t.Errorf("b.go, cached: got %q, want %q", got, "init B")
	}
	if got := names(inFile(results, filepath.Join(real, "b.go"), pathResolver{})); got != "init" {
		t.Errorf("b.go, fresh: got %q, want %q", got, "init")
	}
}
