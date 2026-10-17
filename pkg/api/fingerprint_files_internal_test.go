package api

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// Every path FingerprintFiles is given must name a file with source: the
// inputs a diff treats as an absent side are errors here.
func TestFingerprintFiles_InputErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.go", "package p\n\nfunc F() int { return 1 }\n")
	empty := write("empty.go", "")
	blank := write("blank.go", " \n\t\n")
	big := write("big.go", "package p\n"+strings.Repeat(" ", models.MaxSourceFileSize))
	missing := filepath.Join(dir, "missing.go")

	// good.go is outside a module, so it takes the single-file loader.
	var loads []string
	origSingle := fingerprintSource
	t.Cleanup(func() { fingerprintSource = origSingle })
	fingerprintSource = func(f, src string, policy ir.LiteralPolicy, strict bool, keep func(string) bool) ([]diff.FingerprintResult, error) {
		loads = append(loads, f)
		return origSingle(f, src, policy, strict, keep)
	}

	got := FingerprintFiles(RealFileSystem{}, []string{good, empty, blank, big, missing, "", good}, false)
	if len(got) != 6 {
		t.Errorf("%d entries; want one per distinct path (6)", len(got))
	}
	if len(loads) != 1 || loads[0] != good {
		t.Errorf("loaded %v; want good.go once, though it is listed twice", loads)
	}
	if r := got[good]; r.Err != nil || len(r.Results) == 0 {
		t.Errorf("good.go: %+v; want its functions", r)
	}
	for path, want := range map[string]string{
		empty:   "input source code is empty",
		blank:   "input source code is empty",
		big:     "exceeds maximum analysis size",
		missing: "failed to stat",
		"":      "failed to stat",
	} {
		r, ok := got[path]
		if !ok || r.Err == nil || !strings.Contains(r.Err.Error(), want) {
			t.Errorf("%q: %+v (present %v); want an error containing %q", path, r, ok, want)
		}
		if len(r.Results) != 0 {
			t.Errorf("%q: %d results alongside the error", path, len(r.Results))
		}
	}
}

// panicFS panics reading one file.
type panicFS struct {
	RealFileSystem
	panicOn string
}

func (p panicFS) ReadFile(name string) ([]byte, error) {
	if name == p.panicOn {
		panic("synthetic")
	}
	return p.RealFileSystem.ReadFile(name)
}

// A panic in the FileSystem fails its file only.
func TestFingerprintFiles_FileSystemPanic(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.go"), filepath.Join(dir, "b.go")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := FingerprintFiles(panicFS{panicOn: a}, []string{a, b}, false)
	if err := got[a].Err; err == nil || !strings.Contains(err.Error(), "panic while reading") {
		t.Errorf("a.go: %v; want the panic as its error", err)
	}
	if got[b].Err != nil || len(got[b].Results) == 0 {
		t.Errorf("b.go: %+v; want its functions", got[b])
	}
}

// strict reaches the canonicalizer on the grouped path, the single-file
// path, and the single-file fallback of a group whose fingerprinting fails
// (the route a strict-mode panic takes in a module).
func TestFingerprintFiles_StrictReachesBothPaths(t *testing.T) {
	root := t.TempDir()
	for name, src := range map[string]string{
		"m/go.mod":      "module example.com/m\n\ngo 1.22\n",
		"m/p/p.go":      "package p\n\nfunc P() int { return 1 }\n",
		"loose/main.go": "package main\n\nfunc main() {}\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	var groupStrict, singleStrict []bool
	failGroup := false
	origPkgs, origSingle := fingerprintPackages, fingerprintSource
	t.Cleanup(func() { fingerprintPackages, fingerprintSource = origPkgs, origSingle })
	fingerprintPackages = func(pkgs []*packages.Package, policy ir.LiteralPolicy, strict bool, keep func(string) bool) ([]diff.FingerprintResult, error) {
		mu.Lock()
		groupStrict = append(groupStrict, strict)
		mu.Unlock()
		if failGroup {
			panic("synthetic group failure")
		}
		return origPkgs(pkgs, policy, strict, keep)
	}
	fingerprintSource = func(f, src string, policy ir.LiteralPolicy, strict bool, keep func(string) bool) ([]diff.FingerprintResult, error) {
		mu.Lock()
		singleStrict = append(singleStrict, strict)
		mu.Unlock()
		return origSingle(f, src, policy, strict, keep)
	}

	paths := []string{filepath.Join(root, "m/p/p.go"), filepath.Join(root, "loose/main.go")}
	for _, strict := range []bool{true, false} {
		groupStrict, singleStrict = nil, nil
		for path, r := range FingerprintFiles(RealFileSystem{}, paths, strict) {
			if r.Err != nil {
				t.Fatalf("strict=%v %s: %v", strict, path, r.Err)
			}
		}
		if len(groupStrict) != 1 || groupStrict[0] != strict {
			t.Errorf("strict=%v: grouped path got %v", strict, groupStrict)
		}
		if len(singleStrict) != 1 || singleStrict[0] != strict {
			t.Errorf("strict=%v: single-file path got %v", strict, singleStrict)
		}
	}

	failGroup = true
	for _, strict := range []bool{true, false} {
		singleStrict = nil
		for path, r := range FingerprintFiles(RealFileSystem{}, paths, strict) {
			if r.Err != nil {
				t.Fatalf("failed group, strict=%v %s: %v", strict, path, r.Err)
			}
		}
		// The module file falls back, and the loose file loads alone.
		if len(singleStrict) != 2 || singleStrict[0] != strict || singleStrict[1] != strict {
			t.Errorf("failed group, strict=%v: single-file loads got %v", strict, singleStrict)
		}
	}
}
